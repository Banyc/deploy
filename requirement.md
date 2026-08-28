# The Constitution

This is what the operator actually needs:
- Push this release.
- Return to that deployment.
- Keep these artifacts.
- No disk usage leak — clean up what you create once it stales.
- Show what is currently running.

everything else derives from and serves these rules.


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
deployment slot = a binding of one top-level server to one variant under an ID, with an absolute deploy_dir, declared inside the variant file that owns the workload; its `targets` list binds it to one or more targets
physical binding = a slot's `{server, deploy_dir}` pair at a point in time: the exact on-host deployment location; snapshots record it so exact rollback can verify a slot still lives where it was deployed
target      = a named group of slots (derived from the slots' `targets` lists) plus its ROLLOUT policy; retention is SLOT-OWNED (see "Protection and retention")
deployment  = an attempted push and its exact per-server assignments
generation  = one placement slot's durable activation record for one assignment
```

Deployment, operation, and generation IDs are opaque collision-resistant IDs (UUIDv7 in schema version 1). They identify events and are never used as content identity.

Tree objects contain no release- or variant-specific metadata, so identical trees can be deduplicated safely. Release records bind variants to trees and freeze the release's own canonical per-variant slot declarations (the slot snapshot).

The canonical release ID is derived from a versioned canonical identity payload covering the name-sorted per-variant mapping digests, the name-sorted per-variant SLOT DECLARATION digest (each variant's `[[slots]]` entries canonicalized to their identity fields `id`/`server`/`deploy_dir`/`target` (the slot's ONE owning target, kept verbatim), with `groups` sorted and DEDUPLICATED, so duplicate group names never shift identity — `deploy_dir` lexically normalized — and sorted by slot id), all declared `variant → tree digest` bindings, and the name-sorted per-variant activation and verification behavior-contract digest. It explicitly excludes the resulting release ID, creation time, display name, and provenance, avoiding a circular hash. Two variants may share tree bytes while still requiring different activation and verification behavior, so behavior is captured per variant rather than once per release. A slot-only change — rebinding a slot to another server, moving its `deploy_dir`, or changing its target membership — produces a NEW release ID: the canonical slot declarations are part of the identity, and the release record persists them as its slot snapshot. Capacity is NOT part of the release identity: it is a per-server policy declared on the server entry and resolved from the caller's current configuration at preflight time, so a server-capacity change never produces a new release. Its stored form is `rel-sha256-<release-digest>`; the CLI may display and accept an unambiguous digest prefix. Git revision and creation time are provenance only because mapped inputs can include generated or untracked files. The digest is never trusted from the stored `release_sha256` field: every read (`store.read_release`) and every publish (`helper.publish_release`) recomputes the canonical digest from the record's own content (slot snapshot, bindings, provenance digests) and verifies it against BOTH `release_sha256` and `release_id`, failing closed with an integrity error on any mismatch — a record whose content was edited while the digest fields were left unchanged is rejected. An EMPTY slot snapshot is rejected outright: a current-format record must persist its canonical slot declarations, so a tampered record whose `slots` map was emptied can no longer bypass verification (no legacy escape hatch). `store.write_release` verifies the INCOMING record from its content before creating anything, and re-verifies the EXISTING record from its content before comparing identities, so a same-id record with different content always fails between two content-verified records — never by trusting the stored digest fields. `store.read_release(id)` additionally binds the record to the read path: the stored `release_id` must equal the requested `id`, else an integrity error names both (a record swapped into the wrong release directory is refused, not returned).

Mapping and behavior digests are computed from versioned canonical data after schema defaults, path normalization, and validation, not from TOML formatting, comments, or key order. The original configuration remains available as provenance, while `behavior.json` records the canonical behavior contract. Snapshot files are written atomically and immutably with create-or-compare semantics: an identical rewrite is an idempotent no-op, and replacing an existing release's `behavior.json` with different content fails. A historical deployment restores the variant's original activation and verification behavior from this snapshot (so a variant renamed or removed after the release was created still rolls back exactly), and resolution fails closed: a missing or corrupt historical behavior snapshot aborts the attempt during preflight rather than silently substituting the caller's current configuration or defaults. The snapshot is cross-checked against the release identity on every read and publish: `store.read_release_behaviors` and the remote behavior publication parse the serialized `behavior.json`, recompute the canonical name-sorted per-variant contract digest (`release.variant_behaviors_digest`), and compare it against the release record's provenance `behavior_sha256` (itself folded into `release_sha256`); a snapshot whose canonical contract set digests to anything else — a deleted or changed identity-bearing field, a removed variant, or unparseable bytes — fails closed with an integrity error naming the release and the expected vs recomputed digest, so a tampered `behavior.json` is never returned as the historical contract and never published. Only a payload that parses to the SAME canonical contract set (e.g. JSON key reordering that deserializes identically) passes — that is the "unless the canonical behavior digest remains equal" clause. Capacity headroom, by contrast, is a per-server policy that is never snapshotted: servers have no per-release history, so every push — HEAD or historical — resolves it from the caller's current `deploy.toml`. Retention is SLOT-OWNED configuration declared inside the VARIANT FILE that declares the slot (each slot has exactly ONE policy — its owning variant's — never a per-target policy and never a union across the slot's member targets), and is read from the caller's current configuration on every push.

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
# Inspect the target's deployment history — each line is prefixed with the
# DEPLOYMENT ID of the snapshot that attempt produced (the exact rollback
# key); `-` means the attempt produced no snapshot.
deploy log production
# Inspect the actual generation on every server.
deploy status production
# Restore the exact stored state from an earlier deployment
# (jj-style: the target is passed once; the reference is relative).
# ROLLBACK PAYLOADS ARE KEYED BY DEPLOYMENT ID: `@`, `@-`, `@--` and
# parent(...) walk the target's DEPLOYMENT HISTORY (each successful
# deployment IS a rollback payload keyed by its id; failed attempts never
# resolve).
deploy push production @-              # the previous successful deployment
deploy push production 'parent(@, 3)'    # three deployments back
deploy push production deploy-0190a1b2-3c4d-7e6f-8a9b-0c1d2e3f4a5b  # exact state of that deployment
# Establish a monotonic HISTORY FLOOR at a successful deployment
# (IRREVERSIBLE — requires --yes; --dry-run previews the discard list):
deploy checkpoint production deploy-0190a1b2-3c4d-7e6f-8a9b-0c1d2e3f4a5b --dry-run
deploy checkpoint production deploy-0190a1b2-3c4d-7e6f-8a9b-0c1d2e3f4a5b --yes
```

`deploy log` output is one line per recorded attempt, newest last, each line
prefixed with the DEPLOYMENT ID of the snapshot that attempt produced — the
exact rollback key the push reference grammar accepts (`deploy push <target>
<deployment-id>`); attempts that produced no snapshot — failed or degraded —
render `-` so the columns stay aligned:

```
deploy-0190a1b2-3c4d-7e6f-8a9b-0c1d2e3f4a5b  deploy-0190a1b2-3c4d-7e6f-8a9b-0c1d2e3f4a5b  Successful  2026-08-21T10:20:00Z
-                                            deploy-0190a1b2-3c4d-7e6f-8a9b-0c1d2e3f4a5b  FailedPreflight  2026-08-22T09:15:00Z  (preflight failed)
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

`@` is equivalent to the default too. `HEAD` means "materialize the currently mapped local files" rather than "use only Git-tracked bytes." Pushing identical content reuses the existing local release and tree objects. It is a complete no-op only when reconciliation also shows that every target server already has the intended assignment and passes verification; otherwise the push repairs or completes the remote state.

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
# The deploy.toml format version. The loader accepts EXACTLY this version
# (CONFIG_SCHEMA_VERSION); the doc-consistency test renders this value from
# the constant and keeps it in sync.
schema_version = 2
application = "example"
release = "v1"              # the release directory is forced to releases/v1/

[[pins]]
release = "rel-sha256-41da2f63a950c8494c3c0f1663cf15aacf35b209293b36d3d5c59f8f022805f1"
reason = "known-good recovery release"

# Targets carry ROLLOUT behavior only — retention is slot-owned (declared in
# the variant file that owns each slot).
[targets.production]
rollout = { batch_size = 1, stop_on_failure = true, failure_policy = "rollback_changed" }

# Servers are declared once; slots are declared inside the variant files and
# bind themselves to their ONE owning target with their `target` field (a
# target's members are derived from the slots). Capacity is a per-server
# policy, shared by every deployment slot on the server and resolved from
# this file at preflight time — it is never part of a release.
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
```

Servers and targets are declared once at the top level of `deploy.toml`;
slots are declared inside the variant files. Each slot binds one server to the
variant whose file declares it, names an absolute `deploy_dir`, and carries a
`target` field naming its ONE owning target — a target's member slots
are DERIVED by scanning every variant's slots for that target name, and
`groups` may add rollout-group membership for
`deploy push <target> --group <name>`. Two slots may share one server in
different targets, but within a single target each server appears at most once
(one running generation per server). A slot's `groups` list must not repeat a
name: a duplicate adds no membership yet would change the release identity, so
it is rejected at load (the canonical slot form also deduplicates defensively). Besides `id`,
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
entries of the file, whose `targets` list binds each slot to one or more
top-level targets; retention is declared once per slot — inside
the owning variant file:

```toml
# releases/v1/standard.toml
# All `from` paths are relative to the release directory (`releases/v1/` — the
# project structure is forced), so artifact sources live under `artifacts/`.
description = "Standard deployment"

# The slot-owned retention policy (applied on every retention pass of the slots this
# variant file declares).
[retention.per_server]
keep_distinct_artifacts = 5
keep_days = 14
protect_previous = true

[retention.deployment]
protect_deployments = 2

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

A mapping's `from` is relative to the release directory (`releases/<release>/`) and must remain beneath it. Absolute and escaping source paths are rejected. Recursive directory mappings merge directories; collisions are handled by the strict mapping semantics (overlapping destinations are rejected up front, before any staging write).

Supported mapping controls should include:

```toml
# releases/<release>/mapping-example.toml — a complete variant file showing
# every mapping control the strict loader accepts.
description = "Mapping controls"

[[artifact.mappings]]
from = "artifacts/local/"   # relative to the release directory
                            # (`releases/<release>/`); must remain beneath it
to = "app/"                 # artifact-relative destination
recursive = true
mode = "preserve"           # or an explicit octal mode such as "0644"

[verification]
adapter = "command"
argv = ["true"]
timeout_seconds = 5
```

Mappings are applied in declaration order. Overlapping destinations are rejected up front, so a collision can never be resolved by declaration order or by a `conflict` control: the only mapping control beyond the destination itself is `mode` (`preserve` or an explicit octal mode). Mapping `from` paths are rendered through the template module (`src/template.rs`) with the fixed set of 13 elected variables (see the activation paragraph above). At materialization only the per-variant subset is available: `variant`, `application`, and `release` — where `release` is the release NAME from `deploy.toml`, not the immutable `ReleaseId` (the `ReleaseId` is derived from the materialized trees, so rendering it into a tree would be a circular digest). Every per-slot and per-server variable (`deploy_dir`, `target`, `server`, `user`, `address`, `port`, `slot`, `deployment_id`, `generation`, `tree`) fails loudly at materialization: trees are content-addressed and shared across slots, so target name, server, environment variables, and machine state cannot influence a tree — all servers assigned the same release variant must receive the same digest. Activation (unit-file content) and verification (`argv`) render with the full slot context, where `release` is the deployed artifact's immutable `ReleaseId`. Unknown variables, expressions, filters, and malformed templates fail loudly; the mapper does not implicitly template file contents — unit files and argv are rendered explicitly at activation/verification time.

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
      retention-debt.json
      ledger.jsonl              # ONE ordered history ledger (see below)
  slots/
    app-1/
      observed.json        # the slot's ONE physical observed state (targets are selection views)
  servers/
    server-01.json
    server-02.json
    server-03.json
  deployments/
    <deployment-id>/
      plan.json
  pins.json                  # optional store-global artifact retention pins
```

### ONE history ledger per target

A target's ENTIRE deployment history lives in ONE ordered, append-only JSONL
file: `targets/<target>/ledger.jsonl`. Each line is either the DURABLE
INTENT of a deployment (a `{"kind":"intent", ...}` record: deployment_id,
target, membership, behavior digest, `desired` / `pre_push` per-slot maps —
appended BEFORE any remote mutation, the append-attempt contract) or its
TERMINAL EVENT (a `{"kind":"terminal", ...}` record: the status, the
per-slot outcomes, and — when the deployment was SUCCESSFUL — the ROLLBACK
STATE: the snapshot payload of per-slot generation refs, the behavior
digest, the physical bindings (`{server, deploy_dir}`), and the release the
generations came from). A merged entry (intent + optional terminal) is the
deployment's full record, keyed by its deployment_id; the ledger's append
order IS the history order, and a successful entry's position in the
successful chain is its `sN`. An entry WITHOUT a terminal event is the
CURRENT/INCOMPLETE state — the recoverable pending (in-flight) deployment
that the next push reconciles.

The old multi-file model — `attempts.jsonl` intents + the
`refs/snapshots.jsonl` op log with explicit indices +
`refs/last-successful` + per-deployment `results.json` / `transitions.jsonl`
+ the `history-floor.json` marker + the `cleanup-pending.json` debt flag —
is GONE: the ledger replaces all of it. `deploy log` renders the ledger;
`deploy push <target> <deployment-id>` resolves the ledger entry; `@-`,
`parent(...)` walk the ledger's successful entries.

### Checkpoints (retained-suffix replacement + global sweep)

A checkpoint (`deploy checkpoint <target> <deployment-id>`) retains the
target's history suffix at the checkpoint deployment and sweeps the
unreachable rest. It is exactly three steps:

1. CALCULATE THE RETAINED SUFFIX — everything at/after the checkpoint
   deployment's position in the ledger. The floor is IMPLICIT: the ledger's
   first entry is the oldest retained rollback state; there is NO separate
   floor marker. The checkpoint deployment must be a SUCCESSFUL deployment
   of the target (its entry carries a rollback state).
2. ATOMICALLY REPLACE the ledger with that suffix — temp + fsync +
   chmod-private + rename + parent-directory fsync. THIS is the checkpoint's
   ONLY LOGICAL COMMIT: a reader never observes a torn ledger (wholly old
   or wholly new). IF THE REPLACEMENT FAILS, NO DELETION HAPPENS — the
   checkpoint is a plain error and the full history stands untouched.
3. BEST-EFFORT GLOBAL SWEEP of the unreachable deployment directories
   (`deployments/<id>/`), release records (`releases/<release-id>/`), and
   tree objects (`objects/sha256/<digest>/`). The reachability scan is
   recomputed FRESH on every retry and keeps everything reachable from
   ANOTHER target's ledger, the current/incomplete state (observed
   artifacts, pending intent-only entries, in-flight deployment dirs), or a
   PIN (a release pin marks every variant/tree of its release). A failed
   sweep is retried by RECOMPUTING reachability — no persisted deletion
   worklist, no cleanup-pending debt flag, no backup. Sweeps are
   best-effort and are NOT secure erasure.

Because the atomic replacement is the only logical commit, a failed
checkpoint leaves EXACTLY the pre-call state; a failed sweep leaves the
ledger compacted (the commit stands) with the sweep retry-required, and the
next same-deployment checkpoint recomputes the same suffix (the ledger
already IS it) and re-runs the sweep to convergence. The report carries at
most: the logical commit status + sweep completed / retry-required. The
old floor-marker/backup/restore/torn-advance machinery and the
cleanup-pending debt flag with its three report flags are UNNECESSARY and
were REMOVED. The CLI requires an explicit deployment id and `--yes` for the
real operation; `--dry-run` enumerates exactly what would be discarded and
touches nothing.

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
  "release_schema_version": 2,
  "release_id": "rel-sha256-41da2f63a950c8494c3c0f1663cf15aacf35b209293b36d3d5c59f8f022805f1",
  "release_sha256": "41da2f63a950c8494c3c0f1663cf15aacf35b209293b36d3d5c59f8f022805f1",
  "created_at": "2026-08-21T10:15:00Z",
  "provenance": {
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

This separation allows two releases or variants with identical bytes to share one tree safely. The `slots` member is the release's OWN canonical per-variant slot snapshot — each variant's `[[slots]]` declarations in canonical form (`id`/`server`/`deploy_dir`/`targets`, `deploy_dir` lexically normalized, `targets` sorted, slots sorted by id) — frozen into the record and folded into the release digest. Historical and rollback pushes resolve slot→variant bindings from this snapshot rather than the caller's current variant files. A record with an EMPTY slot snapshot (the pre-snapshot shape) is rejected at the store boundary: `write_release` refuses to persist it and `read_release` refuses to return it, so the old current-config fallback for `slots`-less records is unreachable for any verified record (fail closed). Release records and tree objects are immutable; attempts to replace an existing ID or digest with different content fail.

Local target state is a mirror and cache, not unquestioned authority. Before a mutating operation, the tool reconciles it with the actual remote generation, object inventory, and in-progress transaction state. If a remote retains a
verified tree that is missing locally, reconciliation downloads it into local staging, verifies its canonical digest, and republishes it into the local object store. Remote artifact cleanup remains ROTATION's responsibility (per server, under the mutation lock); the checkpoint's local GC (below) never contacts servers. The only LOCAL artifact deletion path is the checkpoint's reachability-based garbage collection: it deletes release records and tree objects that are unreachable from every target's retained history, observed state, retained deployment records, and pins — a checkpoint can never delete content a server still runs, because the current observed artifact of every target is always in the retained set.

The local store is created with permissions accessible only to its owning user. The system treats all tree bytes as confidential because it cannot know which files contain sensitive material. It never logs file contents; manifests and logs contain paths, modes, and digests only.


### Local artifact garbage collection (checkpoints) and pins

A checkpoint's post-commit maintenance ends with a GLOBAL, best-effort
ARTIFACT GARBAGE COLLECTION pass (`src/store/gc.rs`): after the history
floor + compaction succeed, it scans the WHOLE local store, computes the
RETAINED SET of complete artifact bindings `(release_id, variant,
tree_digest)`, and unlinks every `releases/<release-id>/` directory and
`objects/sha256/<digest>/` directory that is NOT in it. Retaining a binding
keeps BOTH its release record and its tree object.

GC is GLOBAL because release records and tree objects are content-addressed
and SHARED: the same release or tree can be referenced by many targets, so
the retained set cannot be computed per target. It is derived from:

1. Every snapshot at/above every target's history floor — and, for a target
   WITHOUT a floor, its complete history (the same floor-gated suffix every
   read path exposes).
2. Every attempt in the same retained suffix (its `desired` assignments).
3. Every retained deployment record, including unfinished operations — every
   `deployments/<id>/` directory the retained history names (and every
   orphaned/torn directory no log names at all), whose `plan.json` carries
   the per-slot artifact references, the `desired_release`, and the plan
   source. A pending/in-progress operation whose deployment is retained
   stays recoverable: its plan's references are retained with it. A
   deployment record BELOW a floor is discarded with the rest of the
   below-floor history (its artifacts are garbage unless another source
   references them).
4. Every target's CURRENT OBSERVED artifact (`observed.json`).
5. Every configured pin (below).
6. Recovery-required local state — the retained deployment plans, the
   observed artifacts, and the release records/tree objects they name; the
   staging area is rebuildable and never retained.

"Disk cleanup" means unlinking the unreachable files/directories and syncing
the affected parent directories (`releases/`, `objects/sha256/`) so the
space can be reclaimed. It is NOT secure physical erasure: SSD firmware,
copy-on-write filesystems, snapshots, journals, and backups may retain old
blocks after the unlink.

The pass is POST-COMMIT MAINTENANCE with the checkpoint's failure contract:
a failure never moves or removes the established floor and never deletes
anything in the retained set — the scan fails CLOSED before any unlink it
cannot prove safe (an unreadable floor, log, plan, observed record, pins
file, or pinned release record aborts the pass) — the durable
`cleanup-pending.json` debt flag records the outstanding cleanup, and the
report says "cleanup incomplete" (the re-run of the same checkpoint retries
and converges). Reachability is RECOMPUTED fresh on every run: no deletion
worklist is ever persisted.

PINS (`<store>/pins.json`) are store-global retention anchors for ARTIFACT
CONTENT ONLY:

```json
{
  "schema_version": 1,
  "releases": ["rel-sha256-..."],                       // whole-release pins
  "bindings": [{"release": "...", "variant": "...", "tree": "..."}]  // exact-binding pins
}
```

A RELEASE pin marks every variant/tree in that release record (the record is
read and its `variants` map is expanded at GC time; a pin whose record is
missing or unverifiable closes the pass — the content it might protect is
never deleted). An EXACT-BINDING pin keeps the `(release, variant, tree)`
triple directly. A pin NEVER keeps an old deployment, attempt, or snapshot
in history — the floor-gated reads and ref resolution stay keyed on the
history floor alone, so pinning a pre-floor deployment's artifacts keeps the
bytes but never the history — and never raises or removes a floor. These
STORE-LEVEL pins are DISTINCT from the retention subsystem's project-file
`[[pins]]` (retention pins protect the REMOTE retained set and are evaluated
only by retention, never by the local GC): the checkpoint flow is store-only
by construction — it never loads `deploy.toml` and never contacts servers —
so its retention anchors live in the store.

The property test (`artifact_gc_properties`, fixed seed 0x5EED_5EED,
bounded cases) drives the whole path over generated targets, histories,
SHARED releases, SHARED trees, pins, incomplete operations, and injected GC
faults and asserts: no reachable/pinned artifact is ever deleted; a pin
never keeps pre-floor history visible; another target's references protect
shared content; without faults every unreachable release/tree is removed;
with faults extra garbage may remain but required content never disappears;
repeating cleanup converges; repeating a completed checkpoint is idempotent;
advancing one target never truncates another target's history.

## Remote storage
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
      <deployment-id>.json   # write-once commit marker
```

Tree objects, release records, and generation records are immutable. Staging uploads may run concurrently because each uses a deployment-specific incoming path that is invisible to activation and retention. The remote mutation lock is acquired before a staged tree is published and held through publication, generation creation, activation, verification, state recording, and retention. Existing objects are reused only after their digest and manifest are verified.

### Immutable datatypes and their guarantees
Every datatype below carries an immutability semantic. For each one: what must never change, the mechanism that guarantees it, and where that mechanism is enforced.

1. **Tree object** — local `objects/sha256/<digest>/root` + `tree.json`, remote `objects/sha256/<digest>/root`.
   *Semantic*: bytes at a digest path always hash back to that digest.
   *Guarantee*: content-addressed identity; an existing object is re-canonicalized before reuse (`store.store_object`), freshly stored content is verified after copy and deleted on mismatch; staged uploads land in deployment-scoped `incoming/<deployment>/<digest>.partial` and become visible via a single same-filesystem rename (`helper.publish_from_incoming`); every activation re-canonicalizes the downloaded tree before `current` moves (`process_server` integrity check).
2. **Release record** — local `releases/<id>/release.json`.
   *Semantic*: a release ID permanently denotes one mapping set, per-variant slot-declaration set, behavior-contract set, and variant→tree binding set.
*Guarantee*: the ID is derived from the canonical identity payload covering the mapping, slot-declaration,
behavior, and binding digests (`release.release_digest`, schema version 2 with `slots_digest`); the record
freezes the canonical per-variant slot snapshot it was built from, so a slot-only change (rebind, `deploy_dir`
move, retarget) produces a new release ID and historical pushes resolve slot→variant bindings from the stored
snapshot; `store.write_release` refuses to replace an existing ID with different content and treats identical
rewrite as idempotent: the INCOMING record is verified from its own content before anything is written (an
unverifiable record — tampered digest fields or an EMPTY slot snapshot — never even creates the release
directory), and an already-existing record is re-verified from its content before the two content-derived
identities are compared. The digest is recomputed and verified on every read and publish: `store.read_release`
and `helper.publish_release` re-derive the canonical digest from the record's own content (slot snapshot,
bindings, provenance digests) and check it against both `release_sha256` and `release_id`, failing closed with
an integrity error on any mismatch, so a tampered record whose content was edited while the digest fields were
left unchanged is never read or published — and an empty slot snapshot is rejected outright (no legacy escape
hatch). REPUBLISHING against an already-present remote record content-verifies the EXISTING remote
`release.json` the same way before treating it as the same release: `helper.publish_release` re-derives the
existing record's digest from its own content and compares that recomputed identity with the incoming
record's, so a corrupted existing remote record (identity-bearing content — mapping digest, behavior digest,
slot snapshot, variant→tree bindings — mutated while `release_sha256`/`release_id` were retained at the
original values) ALWAYS fails closed with an integrity error naming the remote release and the mismatch, and
malformed existing JSON is refused outright, never silently replaced — republishing against a corrupted remote
record can never pass undetected. `store.read_release(id)` also binds the stored record to the read path:
`rec.release_id` must equal the requested `id`, else an integrity error names both ids (a record swapped into
the wrong release directory is refused, not returned). Capacity is deliberately excluded: it is per-server
live configuration, not a release property. Every release record also carries `release_schema_version =
RELEASE_RECORD_SCHEMA_VERSION`, and readers refuse any other version with an error naming it (fail closed),
while the identity payload version (`RELEASE_PAYLOAD_SCHEMA_VERSION`) is frozen into the digest:
`verify_release_identity` re-derives the digest with exactly that payload version, so a release whose identity
was derived from any other payload version fails verification. `store.read_release(id)` also binds the stored
record to the read path: `rec.release_id` must equal the requested `id`, else an integrity error names both
ids (a record swapped into the wrong release directory is refused, not returned). Capacity is deliberately
excluded: it is per-server live configuration, not a release property.
3. **Release snapshots** — `mapping.toml`, `behavior.json` beside the release record.
   *Semantic*: the frozen inputs behind a release ID can never be rewritten in place, not even partially.
   *Guarantee*: atomic create-or-compare writes (`store.write_atomic_cas`: temp file + rename for atomicity; existing content must match byte-for-byte or the write fails); remotely mirrored by `helper.publish_release_file` (exclusive create via `try_write_new`, then semantic-JSON or byte comparison, refuse replace). There is no capacity snapshot: capacity headroom is live per-server configuration read from the caller's current `deploy.toml`.
4. **Generation record** — remote `generations/<gen>/assignment.json` + `root` symlink.
   *Semantic*: once a generation exists, its assignment (deployment, placement slot, release, variant, tree, behavior digest, prior generation) is fixed forever.
   *Guarantee*: generation IDs are fresh UUIDv7 values minted under the operation lock; `helper.create_generation` installs `assignment.json` with exclusive create-or-compare — an ID collision with divergent content fails integrity instead of rewriting history — and the `root` symlink target is derived deterministically from the verified assignment, making crash recovery idempotent. `current` moves only through the compare-and-swap rename in `helper.swap_current`.
5. **Commit marker** — remote `state/commits/<deployment-id>.json`.
   *Semantic*: a recorded commit is a durable fact of that deployment.
   *Guarantee*: the marker is write-once: `helper.write_commit_marker` installs it by exclusive create, and if a marker already exists it must match byte-for-byte (the payload is deterministic in the deployment ID, generation, and participating placement-slot set) or the rewrite fails integrity. A retried or concurrent commit can therefore never alter a recorded fact; a `pending_commit` recovery reusing the original deployment ID either creates the missing marker or confirms the recorded one byte-for-byte.
6. **Deployment plan and results** — local `deployments/<id>/plan.json`, `results.json`.
   *Semantic*: what an attempt intended and produced is fixed once recorded.
   *Guarantee*: written once per unique deployment ID through `write_atomic_cas`; a same-ID conflicting rewrite fails instead of silently rewriting history (`store.write_plan`, `store.write_results`). The deployment's status is not part of these immutable records: it is an append-only transition stream (`deployments/<id>/transitions.jsonl`), deliberately NOT a mutable progress marker file, so status history is never rewritten. The attempt INTENT (`attempts.jsonl`, step 7) is persisted BEFORE any server mutation; `results.json` is the separate outcomes store written after the mutation loop.
7. **Attempt history and rollback snapshots** — `targets/<target>/attempts.jsonl`, `refs/snapshots.jsonl`.
   *Semantic*: recorded attempts (immutable intent, no status, no outcomes) and successful snapshots are append-only facts; entries are never edited or reordered.
   *Guarantee*: append-mode-only writers under the target lock (`store.append_attempt`, `store.append_snapshot`); snapshot indices are assigned monotonically from the current entry count. Each deployment's status is a per-deployment append-only transition stream (`store.append_transition`), one event per line; the LATEST transition is the deployment's current status (`store.latest_status`).
Mutable by design (excluded from these guarantees): observed target state, per-server records, the `last-successful` ref, the per-deployment transition stream, incoming staging areas, transaction records, and all declarative configuration (`deploy.toml`, variant files), which are versioned through the release identity rather than frozen.

Publishing renames a verified incoming directory into `objects/` on the same filesystem. A generation binds a deployment ID, an artifact (release ID + `variant` + tree digest) for a placement slot, the behavior snapshot, and the prior generation. After its files and a durable transaction record have been written and synced, activation creates a temporary symlink beside `current`, atomically renames it over `current`, and syncs the parent directory. This single durable pointer replacement is the per-slot commit point.

There is no independently updated `previous` symlink. The previous successful generation is derived from the immutable generation chain and history. This avoids pretending that two reference updates can be atomic. PLANNED, not yet implemented: on startup or the next connection, the remote helper would reconcile any unfinished transaction with the actual `current` target and either complete its record or restore the prior generation before accepting another mutation. Today the durable transaction records are WRITTEN but never read back: unfinished-attempt recovery is driven by the controller's local attempt and transition records on the next push.

Atomicity is per server, not across a deployment. Deployment consistency is provided by the rollout and compensation policy described below.

## Push transaction
`deploy push <target>` performs the following:
1. Validate the configuration, unique stable server IDs, slot-to-variant bindings, paths, adapter settings, and SSH host identities.
2. Acquire the local application-store lock and target lock in that order. Application-store publication is serialized across targets (local-store retention is planned, not yet implemented — see “Protection and retention”); target history updates are serialized per target.
3. Materialize every declared variant, generate canonical tree objects, and reuse any object whose digest already exists and verifies correctly.
4. Freeze the mapping, activation, verification, and per-variant slot declaration contract; generate or reuse the immutable release record (the canonical slot declarations are part of the release identity, so a slot-only change yields a new release ID).
5. Reconcile every server's actual `current`, object inventory, and unfinished transactions. Recovery must complete before planning a new mutation.
6. Create and durably save the deployment attempt INTENT (expected pre-push generation and desired assignment for every placement slot; no outcomes) BEFORE changing any server, so a crash after servers advanced can never lose the deployment.
7. Before changing any server, prove that every desired tree is available locally. For historical pushes, also require the current target membership to match the historical deployment's stable placement-slot set, and each slot's COMPLETE physical binding — the `{server, deploy_dir}` pair from its current variant-file `[[slots]]` entry — to match the binding the snapshot recorded: a slot rebound to a different server, or moved to a different `deploy_dir` on the SAME server, is refused (an unrecorded legacy binding is unverifiable and refused the same way).
8. Check local and remote capacity with the configured safety headroom (the per-server `capacity` policy read from the caller's current `deploy.toml`). If needed, run the ordinary protected retention under each remote mutation lock before staging, then recheck. The lock is held through the whole retention block by an RAII guard, so an error inside retention releases it on drop — a later operation can always re-acquire the lock. Abort before activation if required space is still unavailable.
9. Upload and verify missing trees in operation-unique incoming paths on every server before activating the first batch. Uploading and staged verification may be parallel, but incoming content is not installable and retention ignores it. A staging failure — like a capacity failure — happens after the attempt intent was persisted (step 14) and before any `current` change, so it ends the attempt `failed_preflight` (never a stranded `in_progress`); any partially uploaded incoming directories are removed best-effort.
10. Process servers in configured batches. For each server, acquire its remote mutation lock and compare `current` with the plan's expected generation. If it differs, fail that server without mutation. Otherwise publish and reverify the tree and release record, create a generation and transaction record, atomically move `current`, run the activation adapter, and run
verification.
11. On per-server activation or verification failure, atomically restore the prior generation, reconcile the prior activation contract, verify the restored service, and record both the failure and compensation result. Compensation renders the restored contract with the PRIOR assignment's identity — the prior artifact's `release`/`variant`/`tree` AND the prior deployment's `deployment_id`/`generation` move together — so a restored unit/argv never mixes the prior artifact with the failed generation's identities. On a first deployment with no prior generation, compensation removes `current` and reverses only adapter resources created by that attempt.
12. If `stop_on_failure` is enabled, do not start another batch after any failure.
13. Under the default `failure_policy: rollback_changed`, compensate every server already advanced by this deployment. Compensation uses a compare-and-swap and restores a server only if `current` still names the generation created by this attempt. If all compensation succeeds, mark the attempt `failed_rolled_back`; otherwise mark it `degraded` and retain the actual mixed per-server state. An optional `leave_changed` policy may retain successful advances deliberately; any attempt with failures under that policy is `degraded`.
14. Record every attempt, not just successful attempts, in `attempts.jsonl` — the immutable INTENT (deployment id, membership, desired assignments, pre-push state; no status, no outcomes) — and refresh `observed.json` from the actual slot generations. The intent is persisted BEFORE any server mutation (right after the plan and the initial `in_progress` transition are written), so a crash after servers advanced to new generations can never lose the deployment: without the durable intent the next push would see every server already at the desired generation and report "Everything up to date" with no attempt/snapshot/ref ever recorded. The actual per-slot OUTCOMES are recorded separately in `deployments/<id>/results.json` after the mutation loop (the outcomes store the snapshot and `observed.json` are built from — never from the intent record). The attempt's status is recorded as an append-only transition on the deployment (`deployments/<id>/transitions.jsonl`): an initial `in_progress` transition, then the final status transition (with a reason when the metadata phase demoted it). A slot may be a member of SEVERAL targets (its on-server `deploy_dir` state is shared). Observed state is stored ONCE PER SLOT (`slots/<slot-id>/observed.json` — the slot's ONE physical record, never replicated per target); the engine's observed refresh writes each advanced slot's record EXACTLY ONCE, and targets are SELECTION VIEWS over the global slot map: `read_observed(target)` returns the physical records of the target's member slots, so every member target's view of a shared slot always agrees with the single physical record (e.g. `deploy status <other>` after a push to a sibling target shows the current generation/artifact for the shared slot).
15. After every slot's server verifies, write an idempotent, write-once commit marker under each participating server's mutation lock (exclusive create; an existing marker must match byte-for-byte). The marker carries the deployment ID, the generation, and the full placement-slot set of the commit. If this metadata phase is interrupted by a transient failure, mark the attempt `pending_commit`; the next push reconciles it before its own no-op check. Reconciliation also covers attempts whose latest transition is `InProgress` — intent durable (persisted before mutation, step 14) but finalization never completed (a crash between `append_attempt` and the finalize marker, or a faulted `write_results`). It loads the eligible attempts (oldest first, latest transition `PendingCommit` OR `InProgress`), verifies that every recorded participant slot still belongs to the target and that each slot's current generation still equals the generation the attempt recorded (fresh status reads), and only then writes the missing markers (under each server's mutation lock, with the original deployment ID) and finalizes the attempt as `successful` through the SAME replay-safe finalizer the normal success path uses (step 16): first persist the recoverable `pending_commit` marker when the latest transition is not already `pending_commit`, then the snapshot entry and `refs/last-successful` (idempotent — a replay never duplicates the snapshot and repairs the ref), and the terminal `Successful` transition LAST, so a crash mid-finalization leaves the attempt's latest transition still `pending_commit` and therefore re-eligible. The verification is read-only; recovery never reactivates or restarts healthy servers. Any membership or generation mismatch changes the attempt to `degraded` (no snapshot entry). An existing marker whose content differs (an integrity conflict — a concurrent controller recorded a different fact, or the remote state diverged) is likewise NOT transient: the conflicting marker is left untouched and the attempt is finalized `degraded` (transition only, no snapshot entry), never stranded `pending_commit` forever. Only transient failures — lock acquisition, status reads, or transport-level marker writes — leave the attempt `pending_commit` for a later retry rather than falsely reporting `successful` or `degraded`.
16. Only an attempt whose commit markers are complete becomes `successful`. Both the normal success path and recovery finalize through ONE replay-safe finalizer that writes the recoverable `pending_commit` marker, then the snapshot entry and `refs/last-successful`, and appends the terminal `Successful` transition LAST (snapshot and ref first, status last, so the attempt is never recorded `successful` while its snapshot is missing); the snapshot log (KEYED BY DEPLOYMENT ID — `deploy push <target> <deployment-id>` restores that deployment's stored state) and `refs/last-successful` advance only for such fully finalized attempts. The snapshot is built from the attempt's OUTCOMES — the per-slot actuals the engine observed on the main path, or `deployments/<id>/results.json` (falling back to the verified desired state when the outcomes were never persisted, e.g. a faulted `write_results`) during recovery — never from the intent record (`attempts.jsonl`), which carries no outcomes.
17. Apply retention under each server's mutation lock using the protection set defined below. The lock is held by an RAII guard for the whole per-slot retention block (retained-set computation plus mark-and-sweep) and released on drop, so an error mid-retention can never leak the lock and block later operations on that slot. Retention is POST-COMMIT MAINTENANCE: by this point the deployment has already committed (servers advanced, snapshot and attempt recorded), so a per-slot retention failure must NOT change the reported outcome — the push still succeeds. Instead the failure is recorded as a persistent debt marker (per target+slot, under the local store) and surfaced as a warning on the push report; later pushes — including no-ops — retry the maintenance under the same lock-guarded retention block and clear the marker once the retention succeeds. The same rule covers a CONTENDED slot lock: if another operation holds the slot's mutation lock when step 17 runs, the retention cannot run now, and the maintenance is deferred exactly like a retention failure — best-effort debt marker (persistence faults are warning-only) plus a warning naming the slot — never silently skipped, never an `Err`. The deferral's debt read/write is NON-FALLIBLE post-commit maintenance: if the marker cannot be read or persisted (a debt-file fault coinciding with the contention), the failure is an explicit warning — "retention debt maintenance deferred: failed to read/write retention debt" — that says the marker was NOT persisted, so no automatic retryability is claimed and a later push re-deferrals; the committed outcome is unchanged either way. After a successful push every slot is therefore either rotated, or carries debt plus a warning, or the deferral is explicitly warned as unpersisted, and the next unlocked push services any marker. The capacity-preflight retention (step 8) is likewise best-effort; only a real capacity shortage fails the push.

The tool never claims target-wide atomicity. It reports `successful`, `pending_commit`, `failed_preflight`, `failed_rolled_back`, or `degraded`, including the actual generation on every server. An attempt that fails before any `current` change is `failed_preflight`: a preflight failure AFTER the attempt intent was persisted (capacity, staging) appends the terminal `FailedPreflight` transition to that attempt (never a stranded `in_progress`); a failure BEFORE the intent could be computed (plan resolution, historical behavior snapshot, handshake) surfaces as the push error with no attempt record at all. A later push always reconciles first and can finish an incomplete commit (see step 15) or repair an incomplete target.

The local target lock prevents competing pushes from the same local store. Expected-generation and compensation compare-and-swap checks prevent a second controller from being silently overwritten. Concurrent controllers can still cause a visible failed or degraded attempt, but cannot create a lost update on an individual server.

If materialization produces an existing release and reconciliation finds the exact desired generation healthy on every server, the command prints `Everything up to date` without creating a deployment attempt. The no-op still verifies the running services, and that verification renders the EXISTING generation's identities — the deployment id, generation id, and tree from the running generation's stored assignment — never the new deployment/generation ids, which would be fabricated because the no-op creates no records. The no-op path ALSO refreshes the per-slot physical observed records (the same shared refresh as the real-push path, built from the existing generation's assignment): a crash-window push that aborted AFTER the remote advanced but BEFORE the observed refresh is finalized by the reconcile and matched here as up to date, so without the refresh a shared slot's physical record — and every member target's view of it — would stay stale/absent. After ANY completed or recovered mutation — a real push, a rollback, or a no-op retry — every member target's observed projection therefore equals the remote assignment (generation and artifact), never a stale or absent entry. The no-op's observed refresh is best-effort post-commit maintenance: a refresh failure warns but never converts the no-op into an error. Existing local
content never suppresses required remote repair.

`--dry-run` materializes and inspects local content and performs read-only remote status queries in disposable staging. It does not publish local objects, recover remote transactions, upload, publish remotely, activate, execute application verification, write history, or rotate. Instead, it reports any recovery that a real push would have to perform.

## Snapshot history and rollback
Every deployment attempt records its immutable intent: target snapshot, behavior contract, pre-push state, desired state, and actual result — carrying NO status (the status lives in the deployment's transition stream). Assignment relationships are expressed through the canonical model types (`ArtifactRef` = release+variant+tree, `GenerationRef` = generation + placement-slot assignment); every per-location map is keyed by the deployment slot ID. Every record carries `deployment_schema_version = SCHEMA_VERSION` and readers accept ONLY that version: a record with any other `deployment_schema_version` is refused at read time with an error naming the version (fail closed — a record from a different schema is never silently interpreted). A successful example is:

```json
{
  "deployment_schema_version": 5,
  "deployment_id": "deploy-0190a1b2-3c4d-7e6f-8a9b-0c1d2e3f4a5b",
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
— while `pre_push` holds the pre-push `SlotAttemptState` per slot, `None` when the
slot was never deployed before. Schema version 1 keyed these maps by server ID
and stored the artifact triple as flat fields; version 2 rekeys to placement
slots and nests the artifact.)

The deployment's status is an append-only transition stream
(`deployments/<id>/transitions.jsonl`), one event per line; the current status
is the LATEST transition. For example:

```jsonl
{"deployment_id": "deploy-0190a1b2-3c4d-7e6f-8a9b-0c1d2e3f4a5b", "status": "in_progress", "recorded_at": "2026-08-21T10:20:00Z", "reason": "attempt started"}
{"deployment_id": "deploy-0190a1b2-3c4d-7e6f-8a9b-0c1d2e3f4a5b", "status": "successful", "recorded_at": "2026-08-21T10:25:00Z"}
```

The target snapshot log contains only fully successful snapshots, KEYED BY THE DEPLOYMENT ID that produced them (`deploy push production <deployment-id>` restores exactly that deployment's stored state). Failed and degraded attempts remain visible through `deploy log production` and `attempts.jsonl`, but are not valid rollback sources (a failed deployment id never resolves). Each snapshot entry records every slot's advanced generation AND the complete physical binding it had (`bindings`, keyed by slot ID — the slot's `{server, deploy_dir}` pair at deployment time): exact rollback maps generations to slots by slot ID, so the recorded binding is what proves a slot still lives at the exact on-host location it was deployed onto.

A commit is authoritative only when the same deployment ID and placement-slot set are committed on every member. This lets a fresh or repaired local store reconstruct successful snapshot history from the servers instead of trusting a stale local ref.

The target's successful chain is derived from its ONE ledger (the retained
suffix after a checkpoint). ALL reference resolution resolves against that
chain: after a checkpoint the first retained successful entry is the oldest
rollback, and a reference beyond the chain — a deployment id discarded by
the checkpoint, or `parent(...)` / `@-` walking past the start — fails
closed with a ref error instead of resolving to a discarded state.

Pushing an older successful reference restores its complete assignment, including the historical behavior contract and different variants on different servers. References are jj-style: the target is passed ONCE (the push argument) and is never repeated in the reference; the `@`-relative forms resolve against that target's snapshot chain.

### ONE RULE: each reference kind consults ONLY its declared TEMPORAL SOURCE

Four temporal sources are declared explicitly, and every push reference resolves against EXACTLY one:

* **HEAD** (`deploy push <target>` / `@`): the CURRENT variant slot declarations. Planning reads only the caller's current configuration — the current variant files and the current physical slots — and is blind to every historical record.
* **`release:<id>`**: that RELEASE's frozen slot→variant and group topology (the release record's OWN canonical slot snapshot), bound onto the CURRENT physical slots under the LOGICAL membership check (physical bindings MAY differ; the logical membership MUST match). The rebinding is EXPLICIT: the plan carries a `RebindingPlan` recording the frozen topology, the membership check, and the current physical slots it binds onto.
* **a deployment rollback** (`deploy push <target> <deployment-id>`, and the `@`-relative / `parent(...)` walk): that DEPLOYMENT's exact per-slot artifact AND physical binding (the rollback payload's generation refs + recorded `bindings`). The caller's current variant files never re-map them.
* **the CURRENT server configuration**: connectivity and live capacity ONLY — it never contributes topology (no reference resolves slot→variant or membership from `deploy.toml`'s servers), and capacity headroom is a per-server policy resolved from the caller's current configuration on every push (servers have no per-release history).

Each kind FAILS when the required identities cannot be reconciled: a deployment rollback whose recorded binding no longer matches the current physical binding refuses; a `release:<id>` whose logical membership no longer matches the target's refuses (the drift check); HEAD with a broken current declaration refuses.

```sh
deploy push production @-              # the deployment BEFORE the latest
deploy push production @--             # two deployments back
deploy push production 'parent(@, 3)'    # three deployments back from the latest
deploy push production release:rel-sha256-41da2f63a950c8494c3c0f1663cf15aacf35b209293b36d3d5c59f8f022805f1  # DIRECT: deploy this release to the current target's slots (cross-target; no snapshot history needed)
deploy push production deploy-0190a1b2-3c4d-7e6f-8a9b-0c1d2e3f4a5b  # EXACT stored state of that deployment
deploy push production deploy-0190a1b2-3c4d-7e6f-8a9b-0c1d2e3f4a5b--  # two deployments before it
deploy push production 'parent(deploy-0190a1b2-3c4d-7e6f-8a9b-0c1d2e3f4a5b, 1)'  # one deployment before it
```

ROLLBACK PAYLOADS ARE KEYED BY DEPLOYMENT ID. The `@` / `parent(...)` forms
walk the target's DEPLOYMENT HISTORY — the snapshot log in deployment order
(each successful deployment IS a rollback payload keyed by its id); positions
are DERIVED from that order, never stored. The old `sN` snapshot-index forms
(`sN`, `sN-`, `sN--`, `parent(sN, M)`) and the release-refid ancestor forms
(`rel-...--`, `parent(<release-id>, N)`) are REMOVED — migrate `sN` to the
deployment id of that snapshot's deployment (`deploy log` shows it), and
reference a release only via `release:<id>`.

The DIRECT release form `release:<id>` (shell-safe: the token starts with the literal `release:` prefix, no slash; the id is a full `rel-sha256-...` id or a hex digest) deploys the named release to the CURRENT target's slots as they are — each slot's variant from the release's OWN stored slot-variant snapshot, each tree from the release's own variant bindings — but ONLY onto a target whose CURRENT slot membership EXACTLY matches the slot set the release record froze for it: the release-versioned membership is derived from the record's canonical slot snapshot as the union over every variant of the slots whose `targets` list contains the destination target (deduplicated by slot id), and compared for set equality with the target's current slot-id membership at PLAN time, before any remote access. Membership drift — a slot added, removed, or renamed since the release was built — is rejected with a rollback error naming the release and the expected vs current slot sets; the comparison is LOGICAL membership only, so physical bindings (`server`/`deploy_dir`) are intentionally allowed to differ. Because the frozen topology is applied onto the CURRENT physical slots, the rebinding is recorded EXPLICITLY: every `release:<id>` plan carries a `RebindingPlan` — the release, the destination target, the frozen slot→variant/group topology (complete, even under a `--group` selection, which narrows only the planned assignments), the logical membership check, and the current physical slots the topology binds onto. The one historically IMPLICIT exception (a historical topology onto current physical slots) is now an explicit, typed artifact in the plan. It is deliberately NOT a snapshot ref: no snapshot-chain stepping, no deployment-snapshot exact physical-binding checks, and NO target snapshot history required — the release may have been built and pushed anywhere (another target, another machine), and a destination with zero snapshots is fully deployable (as long as its current membership matches the release's frozen set). This is the cross-target / direct-release-deployment path; scripts and persistent configuration use the full id.

A deployment-id ref resolves to THAT deployment's stored rollback payload (the snapshot keyed by its id — a failed deployment id never resolves), and the ancestor steps walk N POSITIONS back from it in the deployment history (N = 0 is the deployment itself; positions are DERIVED from the log order, never stored). Every resolution fails closed with a ref error — an empty chain, an unresolvable deployment id, or stepping before the start of the chain — never underflows and never guesses. A deployment ref restores the snapshot's OWN historical per-slot artifacts (variant and tree together); the caller's current variant files never re-map them.

Exact snapshot rollback requires the current target to contain the same stable placement-slot set as the saved deployment AND each slot's complete physical binding to match the binding the snapshot recorded (`bindings[slot]` = the `{server, deploy_dir}` pair from the slot's variant-file `[[slots]]` entry): a slot rebound to a different server — or moved to a different `deploy_dir` on the SAME server — would otherwise receive the historical generations on the wrong host or at the wrong on-server location. A legacy snapshot entry that never recorded the binding (pre-feature lines, or the intermediate server-only `servers` shape) is unverifiable and is refused the same way. Addresses may change and are taken from the current target definition after host-identity verification. If membership has changed or any slot's physical binding changed, exact rollback fails during preflight without modifying a server.

A target-history ref resolves only against the target whose history it came from; cross-target deployment uses a release ref instead.

Rollback never rebuilds a tree. It uses the retained immutable object with the recorded digest. All required objects are checked locally and staged remotely before the first server changes. If an object is missing locally, reconciliation first attempts to recover it from a target server that retains the verified digest. If no verified copy can be recovered, preflight fails and leaves every `current` pointer unchanged.

## Protection and retention
A slot has EXACTLY ONE retention policy, owned by the slot itself: the policy of the slot's OWNING VARIANT (the variant file whose `[[slots]]` entry declares the slot). Targets carry rollout behavior only — there is NO per-target retention policy and NO union across a shared slot's member targets, so different targets cannot make a shared slot retain differently, and changing a slot's target membership never changes its retention. Retention is evaluated per server because servers may have different release and variant histories. A successful deployment is committed back to each server before retention, allowing its generation history to record the deployment ID. Retention does not run if those commit markers cannot be reconciled.

Every generation record (`generations/<gen>/assignment.json`) and commit marker carries the target that created it (the originating target; legacy records written before this attribution existed carry none) — but retention no longer consults attribution: the slot's single owning-variant policy is applied to ALL of the server's generation records, and a tree object is swept only when that one policy does not retain it. Membership is never a retention input.

Capacity preflight reserves the larger of `capacity.reserve_bytes` and `capacity.reserve_percent` of the destination filesystem's TOTAL size after the upload (the percent is a percentage of the filesystem's total bytes, not of the currently available space). Capacity is a per-server policy declared on the server entry (`capacity = { reserve_bytes = ..., reserve_percent = ... }`) and resolved from the caller's CURRENT configuration on every push — HEAD and historical alike, because servers have no per-release history; it is never part of a release snapshot. The check may invoke the same protected retention before staging, but never weakens the retained set merely to make a deployment fit.

For each server, the retained content set is exactly this union:

```text
- the artifact referenced by the current generation
- the prior distinct successful artifact when protect_previous is true
- artifacts referenced by incomplete transactions
- releases selected by durable pins
- the newest keep_distinct_artifacts distinct successful artifact bindings
- artifacts successfully activated less than keep_days ago
- that server's artifacts in the newest protect_deployments commits
```

An artifact binding is `(release ID, variant, tree digest)`. Repeated repair or restart generations for the same binding consume one retention slot, not many.

Pins are controller-side configuration (top-level `[[pins]]` entries in the project file), never server-stored state. The controller evaluates them from its local store when computing each server's retained set (`retention::compute_retained`); servers hold no pin records and never learn them remotely.
Distinct artifacts are ordered by their most recent successful activation. `keep_distinct_artifacts` and `keep_days` are union rules, not conditions that must both match. Age is measured from the binding's most recent successful activation rather than release creation time.

Retention is a mark-and-sweep operation under the remote mutation lock:
1. Reconcile `current`, unfinished transactions, pins, and commit markers.
2. Mark tree objects referenced by the retained artifact bindings.
3. Keep generation, release, and commit metadata by default; metadata is small and continues to explain unavailable historical states.
4. Delete a tree object only when no retained binding or applicable pin on that server references it. A release or generation record may continue to describe a tree that is no longer installed and must report it as unavailable.
5. Remove abandoned operation-specific incoming directories only after their owner transaction has expired and is known not to be running.

Local-store retention is PLANNED, not yet implemented: it would protect the complete set of variants for every release selected by the same count, age, current, prior, deployment-window, pin, remote-inventory, or unfinished-attempt rules across all targets.

Successful snapshot metadata may be
kept indefinitely, but only entries inside the configured protection windows retain release and tree content. An older snapshot entry whose content was rotated remains auditable but is reported as unavailable for rollback. A local tree object is deleted only after no retained release or known remote inventory requires it — today nothing performs that deletion: the local object store is a cache that retention never sweeps, so a tree that is missing locally is always recovered from a retaining server, never deleted out from under a known remote inventory.

Retention runs automatically after a successful, fully recorded push, and is post-commit maintenance: a
retention failure never changes a deployment's reported outcome (the push stays `Ok` with the committed status)
and never fails a later push. When a per-slot retention fails after commit, the push records a persistent debt
marker — `targets/<target>/retention-debt.json` in the local store, keyed by placement slot, holding the
failure reason — and adds a warning to the push report. Every later push (including an up-to-date no-op,
before reporting "Everything up to date") retries the deferred retentions under the slot mutation locks; a
successful retry clears the marker, a failed retry keeps it and keeps warning. The retry is a DISTINCT PHASE
from the push's own fresh step-17 retention: it runs first (before step 17 on the normal path, at the no-op
return), reads the debt marker BEFORE any lock acquisition, and shares the same RAII-guarded retention block
as step 17 — the test-only step-17 phase hook therefore distinguishes the two phases
(`DeferredRetry` vs `FreshStep17`) so tests can target a phase independently. The no-op path never creates
records, but the retry may write/remove the debt marker file itself. The debt maintenance I/O is itself
non-fallible: a read/write/remove failure of the debt marker (post-commit) is reported as a maintenance
warning — a failed read is treated as empty debt, a failed write/remove leaves the marker in place — and is
never an `Err`, so no debt-file fault can turn a committed push (or a no-op) into an error. The same
non-fallible rule covers a CONTENDED slot lock at step 17: the retention is deferred exactly like a retention
failure — a best-effort debt marker plus a warning naming the slot — and the deferral's own debt read/write
failures ride the same warning channel. If the debt read/write fails while the lock is contended, the
marker is NOT persisted and the report says so explicitly ("retention debt maintenance deferred: failed to
read/write retention debt ..."); no automatic retryability is claimed for a deferral without a marker, so a
user can tell a marker-persisted deferral (retried automatically by a later push) from an unpersisted one
(re-deferred by a later push). The committed outcome is unchanged either way. The same
post-commit rule covers the observed projection refresh (which runs right after the terminal status
post-commit rule covers the observed projection refresh (which runs right after the terminal status
transition, before retention): every store operation there — `write_server`, the per-other-target
`read_observed`/`write_observed` propagation, and the push's own `write_observed` — is non-fatal maintenance,
surfaced as a warning, and a store fault never turns a committed push into an error. The observed maps are
projections of already-durable facts, so no debt marker is needed: the next real push to any member target
rebuilds the projections from current state, and retries converge without duplicate history.

Retention may later be exposed as an explicit maintenance command without changing these safety rules.

## Sweep: the two-sided no-leak contract

The Constitution's "No disk usage leak" rule is served by TWO sweep
mechanisms, one per side of the push:

- RECEIVER side (every server's deployment root): swept by ROTATION. The
  slot's single owning-variant retention policy computes the retained digest
  set (`retention::compute_retained`); the mark-and-sweep pass
  (`RemoteHelper::rotate`) deletes every tree object NOT in the retained set
  and every abandoned incoming directory. Generation/release/commit
  metadata is small and kept by design (it continues to explain unavailable
  historical states); the disk usage — the tree content — is reclaimed.
  Pins and retained content survive.
- PUSHER side (the local store): swept by CHECKPOINT. The checkpoint
  atomically replaces the target's ONE ledger with the retained suffix (the
  only logical commit) and then runs the GLOBAL reachability sweep
  (`LocalStore::run_sweep`): unreachable deployment directories, release
  records, and tree objects are unlinked; everything reachable from a
  retained ledger, the current/incomplete state, or a pin survives. The
  checkpoint is a MEANS — the pusher-side sweep — not a Constitution rule.

BOTH sweeps are POST-COMMIT MAINTENANCE, never corrections. A sweep failure
(or a sweep that has not run) never blocks or rolls back the operation that
triggered it and never reports an ordinary failure:

- The receiver's retention runs after the deployment already committed; a
  failure records a durable retention-debt marker
  (`targets/<target>/retention-debt.json`) plus a warning, and the NEXT PUSH
  (real or no-op) retries the retention under the slot's mutation lock and
  clears the marker once it succeeds.
- The pusher's checkpoint sweep is best-effort; an incomplete sweep records
  a durable sweep-debt marker (`<store>/sweep-debt.json`) and the report
  says sweep retry-required, and the NEXT PUSH (not just the next
  checkpoint) retries the sweep — recomputing reachability FRESH, no
  persisted deletion worklist — and clears the marker once it completes.

Both reports surface a pending sweep as a WARNING, never an error: the
checkpoint report's "sweep did not complete" line and the push report's
"post-commit maintenance deferred" warning. The no-leak property
(`sweep::two_sided_sweep_no_leak`, fixed seed 0x5EED_5EED) asserts: after a
retention pass the receiver retains exactly the policy-retained trees (stale
ones gone, pins/retained content survive); after a checkpoint the pusher
retains exactly the reachable artifacts (unreachable releases/objects/
deployment dirs gone, pins survive); the two sides are independent (retention
never touches the pusher's ledger; checkpoint never touches the receiver's
generations); and with sweep faults injected the operation still succeeds,
debt is recorded, and the next push converges the sweep.

## systemd adapter
Systemd support is an optional adapter outside the generic artifact engine. The mapped unit remains an ordinary artifact file whose CONTENT is rendered through the template module (see “Mapping semantics” and “Activation”) with the slot's template context at activation time — `ExecStart={{ deploy_dir }}/current/app/server` resolves per slot, and the tree itself stays slot-independent (content-addressed and shared across slots). The adapter alone knows how to register and activate it. The activation and verification definitions are canonicalized, hashed into the release identity, and copied into each deployment and generation record. A historical push therefore uses its historical behavior contract rather than the caller's current configuration.

Before changing `current`, the helper validates that every declared `artifact_path` exists with the required type in the desired tree. Command verification is executed directly as an argument vector, never through a shell, with the configured deployment identity, timeout, attempt count, and
interval. Success requires a zero exit status within the timeout. Both the unit content and the verification `argv` are rendered with the full slot context — all 13 elected variables (`deploy_dir`, `variant`, `application`, `release`, `target`, `server`, `user`, `address`, `port`, `slot`, `deployment_id`, `generation`, `tree`), where `release` is the deployed artifact's immutable `ReleaseId` — before they are executed; an unknown or malformed template fails activation/verification loudly. Compensation re-runs the PRIOR generation's contract with the PRIOR assignment's identity — `release`/`variant`/`tree` AND the prior deployment's `deployment_id`/`generation` move together via the `with_assignment` context — so a restored slot that switches variants never renders a torn combination (e.g. the prior variant with the desired release, or the prior artifact with the failed generation's deployment id).

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
The initial transport is SSH with strict host-key verification (per-server `known_hosts` or pinned `host_key_fingerprint` — exactly one source per SSH server, enforced at config validation and re-checked defensively at transport construction). An explicit `local://<absolute-path>` server address instead routes the transport to that exact filesystem endpoint; it exists for tests and for local targets. Server IDs, target names, variant names, release IDs, and paths are validated data and are never concatenated into remote shell commands. Bulk tree transfer is a plain bounded ssh stdin channel: each file's bytes are piped to a remote `cat > <path>` command (the target path is shell-quoted, so a path can never smuggle shell metacharacters out of the forced namespace), never a framed binary protocol. Every ssh operation runs through ONE bounded subprocess runner: every `ssh` connection carries `-o ConnectTimeout=10`, which bounds only the CONNECTION phase, and the runner imposes a hard deadline on the whole operation AFTER connection establishment — so nothing is unbounded. The `ssh-keyscan` key-pin step keeps the 10-second bound (native `-T` plus the runner's process-level deadline); every remote command and upload gets a distinct 60-second default (`SSH_COMMAND_TIMEOUT_SECS`: slower than connection establishment, which a slow-but-healthy remote legitimately needs, but bounded so a hung remote cannot stall the push); `exec` keeps its caller-supplied timeout. On deadline the runner KILLS the child (SIGKILL) and then deterministically REAPS it (joins the wait thread that owns the child) before returning a Timeout — an unreachable or dead host fails fast, no operation can hang the transport indefinitely, and no child is ever left uncollected (no kill-vs-wait race, no zombies, no return-before-reap). The stdin payload is written inside the same bounded wait: a >pipe-buffer upload to a remote that stops reading blocks the write, the deadline fires, and the kill closes the pipe (EPIPE, SIGPIPE ignored). A stdin-write failure follows the same rule as the deadline — the wait closure SAVES the write error, always drains and collects the child (`wait_with_output`), and only then returns the saved error — so a timed-out or write-failed upload is killed AND reaped, never an un-collected child (no return-before-reap on the write-error path either).

A small versioned remote helper owns status inspection, locking, object publication, generation switching, transaction-record keeping, adapter invocation, and retention. Client and helper perform a protocol-version handshake before mutation (the negotiated version is recorded under `control/`; schema version 1 speaks protocol 1). Every mutating request carries an operation ID and is idempotent, and each operation's durable per-server transaction record (`transactions/<operation-id>.json`, advanced `prepared` → `committed`/`compensated` by the helper) is written on every mutation. Two items here are PLANNED, not yet implemented: (a) reading those transaction records back so a disconnected client can reconnect and learn whether the operation prepared, committed, compensated, or never began — records are written, but nothing reconciles them on reconnect (unfinished-attempt recovery is driven by the controller's LOCAL attempt/transition records on the next push); and (b) packaging these operations as a single versioned helper binary uploaded beneath each slot's `deploy_dir` — the planned evolution. Neither changes this contract.

If the deployment account cannot create a slot's `deploy_dir`, an administrator must provision that directory once. Privileged systemd control must likewise be provisioned through the fixed, root-owned wrapper and narrowly scoped restart permission described above; `push` does not grant itself privileges.

The remote application root and state are writable only by the deployment account. Artifact permissions may make selected files readable by the runtime service account, but state, incoming content, and manifests are not generally readable. Because the core cannot recognize secrets, users must understand that any sensitive bytes mapped into a tree will be retained in multiple local and remote versions. External credential references are preferred when versioned secret retention is undesirable.

## Required safety properties
- Never modify a published tree object, release record, or generation record.
- Never reuse an object or release ID until its existing contents verify.
- Never point `current` at a partial, unverified, or unrecorded generation.
- Make one atomic `current` replacement the only per-server commit point.
- Require the planned current generation as a compare-and-swap precondition; compensate only a generation still owned by the failing operation.
- Recover or compensate every unfinished transaction before another mutation.
- Hold the server mutation lock across publication, activation, state commit, and retention; staging alone may occur outside it in unique incoming paths.
- Never delete a tree, release, or generation in the computed retained set.
- Never infer deployment success from the local plan; reconcile actual generations and commit markers, and record every attempt (statuses: `successful`, `pending_commit`, `failed_preflight`, `failed_rolled_back`, `degraded`) with per-slot outcomes (`activated`, `failed`, `skipped`, `restored`; a failed slot's `compensated` flag records whether its compensation succeeded — step 11 records BOTH the failure and the compensation result).
- Never describe rollout as atomic; expose partial state explicitly.
- Ensure a release variant always resolves to one canonical tree digest, independent of target or server.
- Snapshot mappings, variant bindings, behavior contract, target placement-slot IDs, pre-push generations, desired generations, timestamps, and actual results.
- Never fail open: a missing or corrupt historical behavior snapshot fails the attempt in preflight instead of falling back to the caller's current configuration or defaults. (Capacity is never snapshotted: it is live per-server configuration read from the caller's current `deploy.toml`, for HEAD and historical pushes alike.)
- Treat all artifact bytes as confidential and never log their contents.

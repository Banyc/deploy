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
### Glossary

Every term below is defined ONCE, canonically, matching the code's types; the rest of this document uses only these definitions.

```text
tree            = immutable filesystem content, identified only by its tree digest
                  (TreeDigest). Trees carry no release- or variant-specific
                  metadata, so identical trees deduplicate safely.
variant         = a name bound to one tree within a release. The variant file
                  that declares the name also owns the artifact mappings, the
                  activation/verification behavior contract, the deployment
                  slots, and the slot-owned retention policy.
artifact        = an ArtifactRef: the immutable (release, variant, tree) binding a
                  slot runs. Every per-slot assignment map is keyed by slot id
                  and carries each slot's OWN artifact ref.
release         = an immutable record binding every declared variant to a tree
                  digest plus the release's OWN canonical per-variant slot
                  declarations (the slot snapshot), folded into the ReleaseId
                  (`rel-sha256-<digest>`). Capacity is never part of a release.
server          = a durable machine identity (ServerDef): a stable server id plus
                  EXACTLY ONE connection form — `local` (pathless; the slot's
                  typed deploy_dir is the SOLE physical root) or `ssh` (host,
                  user, port, and EXACTLY ONE host identity: a dedicated
                  known_hosts file or a pinned `SHA256:` fingerprint) — plus the
                  per-server capacity policy (live configuration, never
                  snapshotted). The server id is the transport-addressing
                  identity; deployment history is keyed by slot id, never by
                  server id.
deployment slot = a binding of one server to one workload under an id, with an
                  absolute typed deploy_dir, declared inside the variant file
                  that owns the workload. A slot belongs to EXACTLY ONE owning
                  target (its `target` field); optional `groups` add rollout
                  selection for `deploy push <target> --group <name>`. The
                  declaring variant file IS the slot's variant binding.
physical binding= a slot's `{server, deploy_dir}` pair at deployment time
                  (PhysicalBinding): the exact on-host deployment location. The
                  ledger's intent and rollback payloads record it so exact
                  rollback can verify a slot still lives where it was deployed.
target          = a named selection view: a top-level `[targets.<name>]` entry
                  carrying ROLLOUT behavior ONLY. Its member slots are DERIVED
                  by scanning every variant's `[[slots]]` entries for that
                  target name; it has no storage of its own beyond its ONE
                  history ledger and its retention-debt marker. Retention is
                  SLOT-OWNED (the owning variant's policy), never per-target.
deployment      = an attempt: one push of one reference to one target, recorded
                  in the target's ONE ledger as an intent line plus (eventually)
                  one terminal event, keyed by its deployment id (DeploymentId,
                  `deploy-<uuidv7>`). "Attempt" and "deployment" name the same
                  record: the intent line is the attempt; the merged entry is
                  the deployment.
generation      = one placement slot's durable activation record on a server
                  (`generations/<gen>/assignment.json` + a `root` symlink): the
                  deployment id, the placement slot, the artifact ref, the
                  behavior snapshot, and the prior generation. `current` points
                  at exactly one generation. Generation ids are fresh UUIDv7
                  values minted under the operation lock.
ledger line     = one physical JSONL line of `targets/<target>/ledger.jsonl`.
                  Exactly two kinds exist: the INTENT (appended BEFORE any
                  remote mutation: deployment id, target, group, the frozen
                  memberships, the frozen physical bindings, the behavior
                  digest, and the desired / pre_push per-slot maps — no status,
                  no outcomes) and the TERMINAL EVENT (appended once at
                  completion: the status, the per-slot outcomes, and — when
                  successful — the rollback payload). A merged entry (intent +
                  optional terminal) is the deployment's full record; an entry
                  WITHOUT a terminal is the CURRENT/INCOMPLETE state the next
                  push reconciles.
snapshot        = the ROLLBACK PAYLOAD of a successful deployment: the complete
                  per-slot generation refs + physical bindings carried by the
                  successful terminal event. A successful deployment IS a
                  snapshot keyed by its deployment id; there is no separate
                  snapshot log, no stored index, and no `refs/last-successful`
                  — positions in the successful chain are DERIVED from the
                  ledger's append order. (The release record's "slot snapshot"
                  and "behavior snapshot" are DIFFERENT frozen inputs — the
                  release's canonical per-variant slot declarations and its
                  frozen mapping/behavior files — never deployment snapshots.)
outcome         = one slot's terminal result (SlotResult): its outcome kind
                  (`activated` / `failed` / `skipped` / `restored`), its
                  post-mutation observation, and whether compensation
                  succeeded. Outcomes live in the terminal event's per-slot
                  map; there is no separate outcomes file.
observed record = the ONE physical observed state of a placement slot
                  (`slots/<slot-id>/observed.json`), written EXACTLY ONCE per
                  slot. Targets are SELECTION VIEWS over the global slot map:
                  `read_observed(target)` filters the physical records of the
                  target's member slots — never a per-target copy.
commit marker   = the write-once remote marker
                  `state/commits/<deployment-id>.json` recording that the
                  deployment id, generation, and placement-slot set committed
                  on a server. A deployment is successful only when every
                  participant's marker exists; an existing marker is never
                  altered (it must match byte-for-byte).
retention debt  = the durable post-commit maintenance markers:
                  `targets/<target>/retention-debt.json` (the receiver-side
                  rotation was deferred for a slot; the next push retries it
                  under the slot's mutation lock) and `<store>/sweep-debt.json`
                  (the checkpoint's global sweep did not complete; the next
                  push recomputes reachability fresh and finishes it). Both are
                  NON-FALLIBLE maintenance: marker read/write failures are
                  warnings, never errors.
sweep           = the best-effort reclamation pass that serves the "no disk
                  usage leak" rule, one per side: the RECEIVER rotation
                  (mark-and-sweep of tree objects + abandoned incoming
                  directories under the slot's single owning-variant policy)
                  and the PUSHER checkpoint sweep (the global reachability GC
                  of deployment dirs, release records, and tree objects). Both
                  are POST-COMMIT MAINTENANCE, never corrections; neither is
                  secure erasure.
checkpoint      = `deploy checkpoint <target> <deployment-id>`: retain the
                  target's history suffix at a successful deployment (an atomic
                  ledger replacement — the only logical commit) and best-effort
                  sweep the globally unreachable content. See "Checkpoint and
                  garbage collection".
```

Deployment, operation, and generation IDs are opaque collision-resistant IDs (UUIDv7 in schema version 1). They identify events and are never used as content identity.

### Topology model

The configuration is ONE graph, declared in exactly two places:

* `deploy.toml` declares the SERVERS (`[[servers]]`: id, connection, the
  exactly-one host identity, the per-server capacity policy), the TARGETS
  (`[targets.<name>]`: rollout behavior ONLY — no storage, no retention, no
  per-target policy), and the optional `[[pins]]` (durable retention anchors
  for release content).
* The variant files (`releases/<release>/<variant>.toml`, one file per
  variant, named by file stem) declare the ARTIFACT MAPPINGS, the activation
  and verification behavior, the slot-owned RETENTION policy, and the
  DEPLOYMENT SLOTS (`[[slots]]`: id, server, deploy_dir, target, groups).

All membership is DERIVED, never stored:

* A target's member slots are the slots whose `target` field names it, scanned
  across every variant. A slot has EXACTLY ONE owning target, so the same slot
  can never be a member of two targets. Two slots may share one server in
  different targets, but within a single target each server appears at most
  once (one running generation per server).
* A slot's `groups` list selects a subset of the owning target's slots for
  `deploy push <target> --group <name>`; groups never own state, policy,
  history, or checkpoints. A duplicate group name is rejected at load.
* A release's OWN slot snapshot is the frozen per-variant canonical slot
  declarations (`id`/`server`/`deploy_dir`/`target`/`groups`, `deploy_dir`
  lexically normalized, `groups` sorted and deduplicated) folded into the
  release id; historical and rollback pushes resolve slot→variant from the
  snapshot, never from the caller's current variant files. Reference kinds
  consult exactly ONE temporal source: HEAD reads the CURRENT slot
  declarations, `release:<id>` the release's frozen topology bound onto the
  current physical slots (logical membership must match), a deployment ref
  the deployment's exact per-slot artifact + physical binding, and the
  current server configuration contributes connectivity and live capacity
  only (it never contributes topology).

Observed state is stored ONCE PER SLOT (`slots/<slot-id>/observed.json` — the
slot's ONE physical record, never replicated per target); the engine's
observed refresh writes each advanced slot's record EXACTLY ONCE, and targets
are SELECTION VIEWS over the global slot map: `read_observed(target)` returns
the physical records of the target's member slots, so a target's view always
agrees with each member slot's single physical record.

History is stored ONE LEDGER PER TARGET: `targets/<target>/ledger.jsonl`
holds the target's ENTIRE deployment history (see "ONE history ledger per
target"), and `targets/<target>/retention-debt.json` holds its deferred
receiver-side retention markers. The store-global records are the slot map
(`slots/`), the server records (`servers/`), the deployment plans
(`deployments/<id>/plan.json`), the content-addressed release records
(`releases/<release-id>/`) and tree objects (`objects/sha256/<digest>/`), the
store pins (`pins.json`), and the sweep-debt marker (`sweep-debt.json`).

Tree objects contain no release- or variant-specific metadata, so identical trees can be deduplicated safely. Release records bind variants to trees and freeze the release's own canonical per-variant slot declarations (the slot snapshot).

The canonical release ID is derived from a versioned canonical identity payload covering the name-sorted per-variant mapping digests, the name-sorted per-variant SLOT DECLARATION digest (each variant's `[[slots]]` entries canonicalized to their identity fields `id`/`server`/`deploy_dir`/`target` (the slot's ONE owning target, kept verbatim), with `groups` sorted and DEDUPLICATED, so duplicate group names never shift identity — `deploy_dir` lexically normalized — and sorted by the canonical total order over those fields), all declared `variant → tree digest` bindings, and the name-sorted per-variant activation and verification behavior-contract digest. It explicitly excludes the resulting release ID, creation time, display name, and provenance, avoiding a circular hash. Two variants may share tree bytes while still requiring different activation and verification behavior, so behavior is captured per variant rather than once per release. A slot-only change — rebinding a slot to another server, moving its `deploy_dir`, or changing its target membership — produces a NEW release ID: the canonical slot declarations are part of the identity, and the release record persists them as its slot snapshot. Capacity is NOT part of the release identity: it is a per-server policy declared on the server entry and resolved from the caller's current configuration at preflight time, so a server-capacity change never produces a new release. Its stored form is `rel-sha256-<release-digest>`; the CLI may display and accept an unambiguous digest prefix. Git revision and creation time are provenance only because mapped inputs can include generated or untracked files. The digest is never trusted from the stored `release_sha256` field: every read (`store.read_release`) and every publish (`helper.publish_release`) recomputes the canonical digest from the record's own content (slot snapshot, bindings, provenance digests) and verifies it against BOTH `release_sha256` and `release_id`, failing closed with an integrity error on any mismatch — a record whose content was edited while the digest fields were left unchanged is rejected. An EMPTY slot snapshot is rejected outright: a current-format record must persist its canonical slot declarations, so a tampered record whose `slots` map was emptied can no longer bypass verification (no legacy escape hatch). `store.write_release` verifies the INCOMING record from its content before creating anything, and re-verifies the EXISTING record from its content before comparing identities, so a same-id record with different content always fails between two content-verified records — never by trusting the stored digest fields. `store.read_release(id)` additionally binds the record to the read path: the stored `release_id` must equal the requested `id`, else an integrity error names both (a record swapped into the wrong release directory is refused, not returned).

Mapping and behavior digests are computed from versioned canonical data after schema defaults, path normalization, and validation, not from TOML formatting, comments, or key order. The original configuration remains available as provenance, while `behavior.json` records the canonical behavior contract. Snapshot files are written atomically and immutably with create-or-compare semantics: an identical rewrite is an idempotent no-op, and replacing an existing release's `behavior.json` with different content fails. A historical deployment restores the variant's original activation and verification behavior from this snapshot (so a variant renamed or removed after the release was created still rolls back exactly), and resolution fails closed: a missing or corrupt historical behavior snapshot aborts the attempt during preflight rather than silently substituting the caller's current configuration or defaults. The snapshot is cross-checked against the release identity on every read and publish: `store.read_release_behaviors` and the remote behavior publication parse the serialized `behavior.json`, recompute the canonical name-sorted per-variant contract digest (`release.variant_behaviors_digest`), and compare it against the release record's provenance `behavior_sha256` (itself folded into `release_sha256`); a snapshot whose canonical contract set digests to anything else — a deleted or changed identity-bearing field, a removed variant, or unparseable bytes — fails closed with an integrity error naming the release and the expected vs recomputed digest, so a tampered `behavior.json` is never returned as the historical contract and never published. Only a payload that parses to the SAME canonical contract set (e.g. JSON key reordering that deserializes identically) passes — that is the "unless the canonical behavior digest remains equal" clause. Capacity headroom, by contrast, is a per-server policy that is never snapshotted: servers have no per-release history, so every push — HEAD or historical — resolves it from the caller's current `deploy.toml`. Retention is SLOT-OWNED configuration declared inside the VARIANT FILE that declares the slot (each slot has exactly ONE policy — its owning variant's — never a per-target policy and never a union; a slot has exactly one owning target), and is read from the caller's current configuration on every push.

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
# Recover a stranded server mutation lock (no-expiry: a held lock never breaks on its own;
# explicit recovery via --yes after confirming the holder died — inspects without --yes,
# recovers with fresh acquisition id and releases leaving the slot free; idempotent):
deploy unlock production p1             # inspect: free or held by '<owner>' (acquisition <id>) with remedy
deploy unlock production p1 --yes       # recover: replace held lock (fresh acquisition) and release — slot free
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
was bypassed. The `local` marker (a pathless local connection kind whose
sole physical root is the slot's deploy_dir) performs no host verification and
needs no identity source. The `deploy init` CLI mirrors the rule: the two identity flags
conflict at parse time, and an SSH `--address` without exactly one of them is
rejected by the init handler.
Trust-on-first-use without a configured identity source is disabled. All configuration is parsed strictly: every config struct carries `deny_unknown_fields`, so an unrecognized key anywhere in `deploy.toml` or in a variant file is rejected at load rather than silently ignored.

Each variant is described by its own file inside the release directory (e.g.
`releases/v1/standard.toml`); there is no explicit variant list to keep in
sync. A variant file owns its artifact mappings, its deployment policies
(activation, verification), AND its deployment slots — the `[[slots]]`
entries of the file, each binding its slot to its ONE owning target via its
`target` field; retention is declared once per slot — inside
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
The local store contains the exact immutable trees sent to servers, immutable release bindings, and the observed state of each slot:

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
file: `targets/<target>/ledger.jsonl`. Each line is exactly ONE OF TWO LINE
KINDS:

* the DURABLE INTENT of a deployment (a `{"kind":"intent", ...}` record:
  deployment_id, target, the membership, the frozen physical bindings
  (`bindings`), the behavior digest, and the `desired` / `pre_push` per-slot
  maps — appended BEFORE any remote mutation, the append-attempt contract), or
* its TERMINAL EVENT (a `{"kind":"terminal", ...}` record: the status, the
  per-slot outcomes, and — when the deployment was SUCCESSFUL — the ROLLBACK
  STATE, the complete per-slot generation refs + physical bindings
  (`{server, deploy_dir}`) that ARE the deployment's snapshot).

A merged entry (intent + optional terminal) is the deployment's full record,
keyed by its deployment_id; the ledger's append order IS the history order.
Snapshots are KEYED BY DEPLOYMENT ID — a successful terminal's rollback
payload IS the snapshot — and there is no stored index and no separate
`refs/last-successful`: a successful entry's position in the successful chain
is DERIVED from the append order. An entry WITHOUT a terminal event is the
CURRENT/INCOMPLETE state — the recoverable pending (in-flight) deployment
that the next push reconciles.

The old multi-file model — `attempts.jsonl` intents + the
`refs/snapshots.jsonl` op log with explicit indices +
`refs/last-successful` + per-deployment `results.json` / `transitions.jsonl`
+ the `history-floor.json` marker + the `cleanup-pending.json` debt flag —
is GONE: the ledger replaces all of it. `deploy log` renders the ledger;
`deploy push <target> <deployment-id>` resolves the ledger entry; `@-`,
`parent(...)` walk the ledger's successful entries.

### Checkpoint and garbage collection

`deploy checkpoint <target> <deployment-id>` retains the target's history
suffix at the checkpoint deployment and sweeps the globally unreachable
rest. It is exactly three steps:

1. CALCULATE THE RETAINED SUFFIX — everything at/after the checkpoint
   deployment's position in the target's ONE ledger (`ledger_suffix`: the
   physical lines from the checkpoint entry's intent line onward). The floor
   is IMPLICIT: the ledger's first entry is the oldest retained rollback
   state; there is NO separate floor marker. The checkpoint deployment must
   be a SUCCESSFUL deployment of the target (its entry carries a rollback
   state); everything strictly before it — older entries, failed attempts
   included, and their `deployments/<id>/` directories — is discarded.
2. ATOMICALLY REPLACE the ledger with that suffix — temp + fsync +
   chmod-private + rename + parent-directory fsync
   (`write_ledger_suffix`). THIS is the checkpoint's ONLY LOGICAL COMMIT: a
   reader never observes a torn ledger (wholly old or wholly new). IF THE
   REPLACEMENT FAILS, NO DELETION HAPPENS — the checkpoint is a plain error
   and the full history stands untouched. From the moment the replacement
   succeeds the checkpoint is IRREVERSIBLY committed, and no post-commit
   sweep failure may surface as an error (each is converted into a report
   with the sweep retry-required and a warning).
3. BEST-EFFORT GLOBAL SWEEP (`run_sweep`) of the unreachable deployment
   directories (`deployments/<id>/`), release records
   (`releases/<release-id>/`), and tree objects (`objects/sha256/<digest>/`).
   The reachability scan (`reachable_set`) is recomputed FRESH on every
   retry — no persisted deletion worklist, no backup. An incomplete sweep
   records a durable sweep-debt marker (`<store>/sweep-debt.json`) so the
   NEXT PUSH (not just the next checkpoint) retries it, recomputing
   reachability fresh; a completed sweep clears the marker. Sweeps are
   best-effort and are NOT secure erasure.

THE RETAINED SET is computed GLOBALLY — release records and tree objects are
content-addressed and SHARED across targets, so the retained set cannot be
per-target. It is the union of:

1. EVERY TARGET'S CURRENT LEDGER (for the checkpointed target, the retained
   suffix AS-IF the atomic replacement already happened — the same
   `LedgerOverride` the dry-run preview and the real execution share, so the
   preview enumerates EXACTLY what the real checkpoint deletes): each
   entry's deployment id (its `deployments/<id>/` dir), the artifacts its
   intent references (`desired` + `pre_push`), and the release + per-slot
   trees of its terminal's rollback payload. A terminal-less entry (pending
   / in-progress) is retained WITH its intent references — the deployment
   is recoverable and its artifacts must stay.
2. THE CURRENT/INCOMPLETE STATE: every slot's physical observed record
   (`slots/<slot-id>/observed.json` — the slot's ONE physical record, never
   replicated per target) — its artifact and its `last_deployment` id. The
   sweep can never delete content a server still runs, because the current
   observed artifact of every target is always in the retained set.
3. EVERY CONFIGURED PIN — the store-level `<store>/pins.json` AND the
   project-file `deploy.toml` `[[pins]]` (the checkpoint loads the caller's
   config for pins only; it never contacts servers). A RELEASE pin marks
   every variant/tree in that release record (the record is read and its
   `variants` map is expanded at GC time; a pin whose record is missing or
   unverifiable closes the pass — the content it might protect is never
   deleted). An EXACT-BINDING pin keeps the `(release, variant, tree)`
   triple directly. A pin NEVER keeps an old deployment, attempt, or
   snapshot in history — the retained set is the LEDGER SUFFIX alone, so
   pinning the artifacts of a pre-checkpoint deployment keeps the bytes but
   never the history — and never raises or removes the implicit floor.

PINS (`<store>/pins.json`) are store-global retention anchors for ARTIFACT
CONTENT ONLY:

```json
{
  "schema_version": 1,
  "releases": ["rel-sha256-..."],                       // whole-release pins
  "bindings": [{"release": "...", "variant": "...", "tree": "..."}]  // exact-binding pins
}
```

FAIL CLOSED: the retained-set computation is a pure read over the WHOLE
store, and every read failure aborts the pass BEFORE any unlink — an
unreadable ledger, observed record, pins file, or release record (a pin
whose record is missing or unverifiable cannot be expanded) must never
produce a PARTIAL retained set, and an UNKNOWN pre-push assignment or
UNKNOWN observed assignment (the slot's live assignment could not be read)
closes the pass with an integrity error — the GC can never delete anything
it cannot verify. A failed pass leaves extra garbage on disk (never less),
which the retry reclaims once the store is readable again.

THE DELETION STAGES are three: deployment directories (`deployments/<id>/`),
release records (`releases/<id>/`), and tree objects (`objects/sha256/<d>/`).
Each stage is TRI-STATE (an already-removed dir from a previous interrupted
pass is a skip) and FAIL CLOSED: any stat, unlink, or fsync failure stops
the stage — the removed counts report exactly the successful unlinks and the
remaining candidates stay pending (planned, never reported as removed). The
reported removal counts are the filesystem delta, never a claim. "Disk
cleanup" means unlinking the unreachable directories and fsyncing the
affected parents (`deployments/`, `releases/`, `objects/sha256/`) so the
space can be reclaimed; it is NOT secure physical erasure (SSD firmware,
copy-on-write filesystems, snapshots, journals, and backups may retain old
blocks after the unlink).

REPORT AND RETRY: because the atomic replacement is the only logical commit,
a failed checkpoint leaves EXACTLY the pre-call state; a failed sweep leaves
the ledger compacted (the commit stands) with the sweep retry-required, and
the next same-deployment checkpoint recomputes the same suffix (the ledger
already IS it — the replacement is an identical rewrite) and re-runs the
sweep to convergence. The report carries at most: the logical commit status
+ sweep completed / retry-required (plus the sweep-debt warning when the
marker could not be persisted). The CLI requires an explicit deployment id
and `--yes` for the real operation; `--dry-run` takes NO locks, writes
NOTHING, and enumerates exactly what would be discarded and touches nothing.

THE TWO-SIDED NO-LEAK CONTRACT: the Constitution's "No disk usage leak" rule
is served by TWO sweep mechanisms, one per side of the push. The RECEIVER
side (every server's deployment root) is swept by ROTATION: the slot's
single owning-variant retention policy computes the retained digest set
(`retention::compute_retained`); the mark-and-sweep pass
(`RemoteHelper::rotate`) deletes every tree object NOT in the retained set
and every abandoned incoming directory. Generation/release/commit metadata
is small and kept by design (it continues to explain unavailable historical
states); the disk usage — the tree content — is reclaimed. A receiver
retention failure records a durable retention-debt marker
(`targets/<target>/retention-debt.json`) and the NEXT PUSH (real or no-op)
retries the retention under the slot's mutation lock and clears the marker
once it succeeds. The PUSHER side (the local store) is swept by the
checkpoint above; an incomplete sweep records `<store>/sweep-debt.json` and
the next push retries it. BOTH sweeps are POST-COMMIT MAINTENANCE, never
corrections: a sweep failure (or a sweep that has not run) never blocks or
rolls back the operation that triggered it, and both reports surface a
pending sweep as a WARNING, never an error.

The checkpoint/GC path is pinned by property tests with the house fixed seed
0x5EED_5EED and bounded cases (`crate::retention::checkpoint`,
`crate::retention::reachability::gc`, `crate::retention::sweep_tests`): the
EXPLICIT COMMIT BOUNDARY (a pre-commit fault — the replacement itself — is a
plain error and the full history stands; a post-commit fault at ANY sweep
stage is converted into an established report with the sweep retry-required
— never an error); the visible ledger is always WHOLY OLD or WHOLY NEW (the
atomic replace); retained and pinned content survives every failure; a
corrupted or unreadable retention anchor (ledger, observed record, pins
file, pinned release record, torn deployment record) aborts the sweep with
ZERO deletions and the repaired retry deletes exactly the unreachable set;
reported removals equal the filesystem delta, pending candidates stay on
disk, and retries converge; an unknown pre-push or observed assignment
fails the sweep closed; another target's references protect shared content;
repeating a completed checkpoint is idempotent; advancing one target never
truncates another target's history; and after a retention pass the receiver
retains exactly the policy-retained trees while after a checkpoint the
pusher retains exactly the reachable artifacts, with the two sides
independent (retention never touches the pusher's ledger; the checkpoint
never touches the receiver's generations) and sweep faults injected the
operation still succeeds, debt is recorded, and the next push converges the
sweep.

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

This separation allows two releases or variants with identical bytes to share one tree safely. The `slots` member is the release's OWN canonical per-variant slot snapshot — each variant's `[[slots]]` declarations in canonical form (`id`/`server`/`deploy_dir`/`target`/`groups`, `deploy_dir` lexically normalized, `groups` sorted and deduplicated, slots sorted by the canonical total order) — frozen into the record and folded into the release digest. Historical and rollback pushes resolve slot→variant bindings from this snapshot rather than the caller's current variant files. A record with an EMPTY slot snapshot (the pre-snapshot shape) is rejected at the store boundary: `write_release` refuses to persist it and `read_release` refuses to return it, so the old current-config fallback for `slots`-less records is unreachable for any verified record (fail closed). Release records and tree objects are immutable; attempts to replace an existing ID or digest with different content fail.

Local target state is a mirror and cache, not unquestioned authority. Before a mutating operation, the tool reconciles it with the actual remote generation, object inventory, and in-progress transaction state. If a remote retains a
verified tree that is missing locally, reconciliation downloads it into local staging, verifies its canonical digest, and republishes it into the local object store. Remote artifact cleanup remains ROTATION's responsibility (per server, under the mutation lock); the checkpoint's local GC (see "Checkpoint and garbage collection") never contacts servers. The only LOCAL artifact deletion path is the checkpoint's reachability-based garbage collection: it deletes release records and tree objects that are unreachable from every target's retained history, observed state, retained deployment records, and pins — a checkpoint can never delete content a server still runs, because the current observed artifact of every target is always in the retained set.

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
6. **Deployment plan** — local `deployments/<id>/plan.json`.
   *Semantic*: what an attempt intended is fixed once recorded.
   *Guarantee*: written once per unique deployment ID through `write_atomic_cas`; a same-ID conflicting rewrite fails instead of silently rewriting history (`store.write_plan`). The deployment's status is NOT part of this record and has NO separate transition stream: it is carried by the ledger's TERMINAL EVENT line, appended once per deployment — the terminal IS the status record, so there is no `results.json` and no `transitions.jsonl`. The attempt INTENT (the ledger's intent line, step 14) is persisted BEFORE any server mutation; the per-slot OUTCOMES live in the terminal event's `outcomes` map, never in a separate outcomes file.
7. **Deployment history and rollback snapshots** — `targets/<target>/ledger.jsonl`.
   *Semantic*: recorded attempts (immutable intent lines, no status, no outcomes) and terminal events (the status, the per-slot outcomes, and — when successful — the complete rollback snapshot) are append-only facts; entries are never edited or reordered.
   *Guarantee*: crash-atomic whole-ledger appends under the target lock (`store.append_intent`, `store.append_terminal` — one atomic line per deployment, temp + fsync + rename). The terminal event carries the deployment's status (there is no separate status-transition stream); the LATEST status is the terminal's status (`store.latest_status`, DERIVED from the ledger — never a mutable marker file). Snapshots are KEYED BY DEPLOYMENT ID: a successful terminal's rollback payload IS the snapshot, and `deploy push <target> <deployment-id>` resolves it from the ledger. There is no `refs/last-successful` (the latest successful entry is DERIVED from the ledger) and no separate snapshot log.
Mutable by design (excluded from these guarantees): observed target state, per-server records, incoming staging areas, transaction records, and all declarative configuration (`deploy.toml`, variant files), which are versioned through the release identity rather than frozen.

Publishing renames a verified incoming directory into `objects/` on the same filesystem. A generation binds a deployment ID, an artifact (release ID + `variant` + tree digest) for a placement slot, the behavior snapshot, and the prior generation. After its files and a durable transaction record have been written and synced, activation creates a temporary symlink beside `current`, atomically renames it over `current`, and syncs the parent directory. This single durable pointer replacement is the per-slot commit point.

There is no independently updated `previous` symlink. The previous successful generation is derived from the immutable generation chain and history. This avoids pretending that two reference updates can be atomic. PLANNED, not yet implemented: on startup or the next connection, the remote helper would reconcile any unfinished transaction with the actual `current` target and either complete its record or restore the prior generation before accepting another mutation. Today the durable transaction records are WRITTEN but never read back: unfinished-attempt recovery is driven by the controller's local records — the target's ledger, whose durable intent lines and reconciling finalizer carry the attempt — on the next push.

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
14. Append the attempt's INTENT LINE to the target's ONE ledger (`targets/<target>/ledger.jsonl`, `store.append_intent`) — the immutable INTENT (deployment id, membership, the frozen physical bindings, desired assignments, pre-push state; no status, no outcomes) — and refresh `observed.json` from the actual slot generations. The intent is persisted BEFORE any server mutation (right after the plan is written), so a crash after servers advanced to new generations can never lose the deployment: without the durable intent the next push would see every server already at the desired generation and report "Everything up to date" with no attempt ever recorded. There is no separate outcomes file (`results.json` is GONE) and no status-transition stream (`transitions.jsonl` is GONE): the per-slot OUTCOMES and the final STATUS are carried by the TERMINAL EVENT line appended when the deployment completes (steps 15-16), never by the intent record. A slot belongs to EXACTLY ONE owning target (its single `target` field); a target's member slots are derived from the slots' declarations, and the same slot can never be a member of two targets. Observed state is stored ONCE PER SLOT (`slots/<slot-id>/observed.json` — the slot's ONE physical record, never replicated per target); the engine's observed refresh writes each advanced slot's record EXACTLY ONCE, and targets are SELECTION VIEWS over the global slot map: `read_observed(target)` returns the physical records of the target's member slots, so every target's view always agrees with the single physical record (e.g. `deploy status <target>` after a push shows the current generation/artifact for exactly that target's member slots).
15. After every slot's server verifies, write an idempotent, write-once commit marker under each participating server's mutation lock (exclusive create; an existing marker must match byte-for-byte). The marker carries the deployment ID, the generation, and the full placement-slot set of the commit. If this metadata phase is interrupted by a transient failure, mark the attempt `pending_commit`; the next push reconciles it before its own no-op check. Reconciliation also covers INTENT-ONLY ledger entries — the intent durable (persisted before mutation, step 14) but the terminal event never appended (a crash between `append_intent` and the finalize marker). It loads the eligible entries (oldest first — an entry with NO terminal event is the recoverable `InProgress`/`PendingCommit` state), verifies that every recorded participant slot still belongs to the target and that each slot's current generation still equals the generation the attempt recorded (fresh status reads), and only then writes the missing markers (under each server's mutation lock, with the original deployment ID) and finalizes the attempt as `successful` through the SAME replay-safe finalizer the normal success path uses (step 16): APPEND THE TERMINAL `Successful` EVENT LAST, so a crash mid-finalization leaves the entry terminal-less and therefore re-eligible. The verification is read-only; recovery never reactivates or restarts healthy servers. Any membership or generation mismatch changes the attempt to `degraded` (a `Degraded` terminal). An existing marker whose content differs (an integrity conflict — a concurrent controller recorded a different fact, or the remote state diverged) is likewise NOT transient: the conflicting marker is left untouched and the attempt is finalized `degraded` (terminal only), never stranded `pending_commit` forever. Only transient failures — lock acquisition, status reads, or transport-level marker writes — leave the attempt `pending_commit` for a later retry rather than falsely reporting `successful` or `degraded`.
16. Only an attempt whose commit markers are complete becomes `successful`. Both the normal success path and recovery finalize through ONE replay-safe finalizer that APPENDS THE TERMINAL `Successful` EVENT to the target's ledger (one atomic line, `store.append_terminal`; replay-idempotent — a repeated finalize for the same deployment id is a no-op). The terminal event carries the status, the per-slot outcomes, AND the COMPLETE ROLLBACK STATE — that rollback payload IS the deployment's snapshot, KEYED BY ITS DEPLOYMENT ID: `deploy push <target> <deployment-id>` restores exactly that deployment's stored state, and there is no separate snapshot log and no `refs/last-successful` ref (the latest successful entry is DERIVED from the ledger). The snapshot is built from the attempt's OUTCOMES — the per-slot actuals the engine observed on the main path, or the verified desired state during recovery — never from the intent record, which carries no outcomes.
17. Apply retention under each server's mutation lock using the protection set defined below. The lock is held by an RAII guard for the whole per-slot retention block (retained-set computation plus mark-and-sweep) and released on drop, so an error mid-retention can never leak the lock and block later operations on that slot. Retention is POST-COMMIT MAINTENANCE: by this point the deployment has already committed (servers advanced, snapshot and attempt recorded), so a per-slot retention failure must NOT change the reported outcome — the push still succeeds. Instead the failure is recorded as a persistent debt marker (per target+slot, under the local store) and surfaced as a warning on the push report; later pushes — including no-ops — retry the maintenance under the same lock-guarded retention block and clear the marker once the retention succeeds. The same rule covers a CONTENDED slot lock: if another operation holds the slot's mutation lock when step 17 runs, the retention cannot run now, and the maintenance is deferred exactly like a retention failure — best-effort debt marker (persistence faults are warning-only) plus a warning naming the slot — never silently skipped, never an `Err`. The deferral's debt read/write is NON-FALLIBLE post-commit maintenance: if the marker cannot be read or persisted (a debt-file fault coinciding with the contention), the failure is an explicit warning — "retention debt maintenance deferred: failed to read/write retention debt" — that says the marker was NOT persisted, so no automatic retryability is claimed and a later push re-deferrals; the committed outcome is unchanged either way. After a successful push every slot is therefore either rotated, or carries debt plus a warning, or the deferral is explicitly warned as unpersisted, and the next unlocked push services any marker. The capacity-preflight retention (step 8) is likewise best-effort; only a real capacity shortage fails the push.

The tool never claims target-wide atomicity. It reports `successful`, `pending_commit`, `failed_preflight`, `failed_rolled_back`, or `degraded`, including the actual generation on every server. An attempt that fails before any `current` change is `failed_preflight`: a preflight failure AFTER the attempt intent was persisted (capacity, staging) appends the terminal `FailedPreflight` EVENT to that attempt's ledger entry (never a stranded `in_progress`); a failure BEFORE the intent could be computed (plan resolution, historical behavior snapshot, handshake) surfaces as the push error with no attempt record at all. A later push always reconciles first and can finish an incomplete commit (see step 15) or repair an incomplete target.

The local target lock prevents competing pushes from the same local store. Expected-generation and compensation compare-and-swap checks prevent a second controller from being silently overwritten. Concurrent controllers can still cause a visible failed or degraded attempt, but cannot create a lost update on an individual server.

If materialization produces an existing release and reconciliation finds the exact desired generation healthy on every server, the command prints `Everything up to date` without creating a deployment attempt. The no-op still verifies the running services, and that verification renders the EXISTING generation's identities — the deployment id, generation id, and tree from the running generation's stored assignment — never the new deployment/generation ids, which would be fabricated because the no-op creates no records. The no-op path ALSO refreshes the per-slot physical observed records (the same shared refresh as the real-push path, built from the existing generation's assignment): a crash-window push that aborted AFTER the remote advanced but BEFORE the observed refresh is finalized by the reconcile and matched here as up to date, so without the refresh the slot's physical record — and its target's view of it — would stay stale/absent. After ANY completed or recovered mutation — a real push, a rollback, or a no-op retry — every target's observed projection therefore equals the remote assignment (generation and artifact), never a stale or absent entry. The no-op's observed refresh is best-effort post-commit maintenance: a refresh failure warns but never converts the no-op into an error. Existing local
content never suppresses required remote repair.

`--dry-run` materializes and inspects local content and performs read-only remote status queries in disposable staging. It does not publish local objects, recover remote transactions, upload, publish remotely, activate, execute application verification, write history, or rotate. Instead, it reports any recovery that a real push would have to perform.

## Snapshot history and rollback
Every deployment attempt records TWO lines in the target's ONE ledger: its immutable INTENT (target, the membership, the frozen physical bindings, behavior contract, desired and pre-push state — carrying NO status and NO outcomes) and its TERMINAL EVENT (the status, the per-slot outcomes, and — when SUCCESSFUL — the COMPLETE ROLLBACK STATE, the deployment's snapshot). The status lives in the terminal event, not in a separate transition stream: there is no `transitions.jsonl` and no mutable progress marker file. Assignment relationships are expressed through the canonical model types (`ArtifactRef` = release+variant+tree, `GenerationRef` = generation + placement-slot assignment); every per-location map is keyed by the deployment slot ID. Every INTENT line carries `deployment_schema_version = LEDGER_SCHEMA_VERSION` and readers accept ONLY that version: an intent line with any other `deployment_schema_version` is refused at read time with an error naming the version (fail closed — a record from a different schema is never silently interpreted; a terminal line whose status/rollback shape cannot be converted is refused the same way). The wire examples below are RENDERED from the real wire records by the doc-example generator (`src/ledger/records/example.rs`) — they are byte-equal to the generator's output (pinned by `tests::docs_examples_match_generated_wire`), so they can never drift from the current wire: the intent's `deployment_schema_version` IS the current `LEDGER_SCHEMA_VERSION`, the strict wire observations are adjacently tagged (`state` + `value`, `deny_unknown_fields`), the frozen memberships and the frozen `entries` are present, and the successful terminal's rollback payload is the snapshot keyed by the deployment id.

<!-- LEDGER WIRE EXAMPLES: generated by src/ledger/records/example.rs (the
     docs-match test byte-compares these blocks against the generator — do
     not edit by hand; a schema change must re-render them). -->

```json
{
  "kind": "intent",
  "deployment_schema_version": 7,
  "deployment_id": "deploy-0190a1b2-3c4d-7e6f-8a9b-0c1d2e3f4a5b",
  "target": "production",
  "slot_ids": [
    "p1",
    "p2",
    "p3"
  ],
  "selected_membership": [
    "p1",
    "p2",
    "p3"
  ],
  "full_membership": [
    "p1",
    "p2",
    "p3"
  ],
  "bindings": {
    "p1": {
      "server": "server-01",
      "deploy_dir": "/srv/deploy/p1"
    },
    "p2": {
      "server": "server-02",
      "deploy_dir": "/srv/deploy/p2"
    },
    "p3": {
      "server": "server-03",
      "deploy_dir": "/srv/deploy/p3"
    }
  },
  "behavior_sha256": "70e91105dab5197be955fb4a57416e3c70e91105dab5197be955fb4a57416e3c",
  "attempted_at": "2026-08-21T10:20:00Z",
  "desired": {
    "p1": {
      "generation": "gen-0190a1b2-3c4d-7e6f-8a9b-0c1d2e3f4a5b",
      "assignment": {
        "placement_slot": "p1",
        "artifact": {
          "release": "rel-sha256-41da2f63a950c8494c3c0f1663cf15aacf35b209293b36d3d5c59f8f022805f1",
          "variant": "standard",
          "tree": "4325b42072048fcfadfc32e0ca6ce0404325b42072048fcfadfc32e0ca6ce040"
        }
      }
    },
    "p2": {
      "generation": "gen-0290a1b2-3c4d-7e6f-8a9b-0c1d2e3f4a5b",
      "assignment": {
        "placement_slot": "p2",
        "artifact": {
          "release": "rel-sha256-41da2f63a950c8494c3c0f1663cf15aacf35b209293b36d3d5c59f8f022805f1",
          "variant": "standard",
          "tree": "256f3a3952ec78031c924ac35af4e591256f3a3952ec78031c924ac35af4e591"
        }
      }
    },
    "p3": {
      "generation": "gen-0390a1b2-3c4d-7e6f-8a9b-0c1d2e3f4a5b",
      "assignment": {
        "placement_slot": "p3",
        "artifact": {
          "release": "rel-sha256-41da2f63a950c8494c3c0f1663cf15aacf35b209293b36d3d5c59f8f022805f1",
          "variant": "high-capacity",
          "tree": "a097975d638a3e06b90b6f7c5515c95aa097975d638a3e06b90b6f7c5515c95a"
        }
      }
    }
  },
  "pre_push": {
    "p1": null,
    "p2": null,
    "p3": null
  },
  "slots": {}
}
```

```json
{
  "kind": "terminal",
  "deployment_id": "deploy-0190a1b2-3c4d-7e6f-8a9b-0c1d2e3f4a5b",
  "target": "production",
  "status": "successful",
  "recorded_at": "2026-08-21T10:25:00Z",
  "outcomes": {
    "p1": {
      "slot_id": "p1",
      "outcome": "activated",
      "observation": {
        "state": "known",
        "value": {
          "generation": "gen-0190a1b2-3c4d-7e6f-8a9b-0c1d2e3f4a5b"
        }
      },
      "compensated": false
    },
    "p2": {
      "slot_id": "p2",
      "outcome": "activated",
      "observation": {
        "state": "known",
        "value": {
          "generation": "gen-0290a1b2-3c4d-7e6f-8a9b-0c1d2e3f4a5b"
        }
      },
      "compensated": false
    },
    "p3": {
      "slot_id": "p3",
      "outcome": "activated",
      "observation": {
        "state": "known",
        "value": {
          "generation": "gen-0390a1b2-3c4d-7e6f-8a9b-0c1d2e3f4a5b"
        }
      },
      "compensated": false
    }
  },
  "rollback": {
    "entries": {
      "p1": {
        "generation": "gen-0190a1b2-3c4d-7e6f-8a9b-0c1d2e3f4a5b",
        "artifact": {
          "release": "rel-sha256-41da2f63a950c8494c3c0f1663cf15aacf35b209293b36d3d5c59f8f022805f1",
          "variant": "standard",
          "tree": "4325b42072048fcfadfc32e0ca6ce0404325b42072048fcfadfc32e0ca6ce040"
        },
        "binding": {
          "server": "server-01",
          "deploy_dir": "/srv/deploy/p1"
        }
      },
      "p2": {
        "generation": "gen-0290a1b2-3c4d-7e6f-8a9b-0c1d2e3f4a5b",
        "artifact": {
          "release": "rel-sha256-41da2f63a950c8494c3c0f1663cf15aacf35b209293b36d3d5c59f8f022805f1",
          "variant": "standard",
          "tree": "256f3a3952ec78031c924ac35af4e591256f3a3952ec78031c924ac35af4e591"
        },
        "binding": {
          "server": "server-02",
          "deploy_dir": "/srv/deploy/p2"
        }
      },
      "p3": {
        "generation": "gen-0390a1b2-3c4d-7e6f-8a9b-0c1d2e3f4a5b",
        "artifact": {
          "release": "rel-sha256-41da2f63a950c8494c3c0f1663cf15aacf35b209293b36d3d5c59f8f022805f1",
          "variant": "high-capacity",
          "tree": "a097975d638a3e06b90b6f7c5515c95aa097975d638a3e06b90b6f7c5515c95a"
        },
        "binding": {
          "server": "server-03",
          "deploy_dir": "/srv/deploy/p3"
        }
      }
    }
  },
  "selected_membership": [
    "p1",
    "p2",
    "p3"
  ],
  "full_membership": [
    "p1",
    "p2",
    "p3"
  ],
  "reason": "push completed"
}
```

<!-- END LEDGER WIRE EXAMPLES -->

The successful chain contains only fully successful terminal events, KEYED BY THE DEPLOYMENT ID that produced them (`deploy push production <deployment-id>` restores exactly that deployment's stored state). Failed and degraded attempts remain visible through `deploy log production` (their ledger entries carry their terminals), but are not valid rollback sources (a failed deployment id never resolves). Each successful terminal's rollback payload records every slot's advanced generation AND the complete physical binding it had (`entries`, keyed by slot ID — each entry's `{generation, artifact, binding}`): exact rollback maps generations to slots by slot ID, so the recorded binding is what proves a slot still lives at the exact on-host location it was deployed onto.

A commit is authoritative only when the same deployment ID and placement-slot set are committed on every member. This lets a fresh or repaired local store re-verify its snapshot history against the servers instead of trusting an unverified local ledger.

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

The DIRECT release form `release:<id>` (shell-safe: the token starts with the literal `release:` prefix, no slash; the id is a full `rel-sha256-...` id or a hex digest) deploys the named release to the CURRENT target's slots as they are — each slot's variant from the release's OWN stored slot-variant snapshot, each tree from the release's own variant bindings — but ONLY onto a target whose CURRENT slot membership EXACTLY matches the slot set the release record froze for it: the release-versioned membership is derived from the record's canonical slot snapshot as the union over every variant of the slots whose `target` field names the destination target (deduplicated by slot id), and compared for set equality with the target's current slot-id membership at PLAN time, before any remote access. Membership drift — a slot added, removed, or renamed since the release was built — is rejected with a rollback error naming the release and the expected vs current slot sets; the comparison is LOGICAL membership only, so physical bindings (`server`/`deploy_dir`) are intentionally allowed to differ. Because the frozen topology is applied onto the CURRENT physical slots, the rebinding is recorded EXPLICITLY: every `release:<id>` plan carries a `RebindingPlan` — the release, the destination target, the frozen slot→variant/group topology (complete, even under a `--group` selection, which narrows only the planned assignments), the logical membership check, and the current physical slots the topology binds onto. The one historically IMPLICIT exception (a historical topology onto current physical slots) is now an explicit, typed artifact in the plan. It is deliberately NOT a snapshot ref: no snapshot-chain stepping, no deployment-snapshot exact physical-binding checks, and NO target snapshot history required — the release may have been built and pushed anywhere (another target, another machine), and a destination with zero snapshots is fully deployable (as long as its current membership matches the release's frozen set). This is the cross-target / direct-release-deployment path; scripts and persistent configuration use the full id.

A deployment-id ref resolves to THAT deployment's stored rollback payload (the snapshot keyed by its id — a failed deployment id never resolves), and the ancestor steps walk N POSITIONS back from it in the deployment history (N = 0 is the deployment itself; positions are DERIVED from the log order, never stored). Every resolution fails closed with a ref error — an empty chain, an unresolvable deployment id, or stepping before the start of the chain — never underflows and never guesses. A deployment ref restores the snapshot's OWN historical per-slot artifacts (variant and tree together); the caller's current variant files never re-map them.

Exact snapshot rollback requires the current target to contain the same stable placement-slot set as the saved deployment AND each slot's complete physical binding to match the binding the snapshot recorded (`bindings[slot]` = the `{server, deploy_dir}` pair from the slot's variant-file `[[slots]]` entry): a slot rebound to a different server — or moved to a different `deploy_dir` on the SAME server — would otherwise receive the historical generations on the wrong host or at the wrong on-server location. A legacy snapshot entry that never recorded the binding (pre-feature lines, or the intermediate server-only `servers` shape) is unverifiable and is refused the same way. Addresses may change and are taken from the current target definition after host-identity verification. If membership has changed or any slot's physical binding changed, exact rollback fails during preflight without modifying a server.

A target-history ref resolves only against the target whose history it came from; cross-target deployment uses a release ref instead.

Rollback never rebuilds a tree. It uses the retained immutable object with the recorded digest. All required objects are checked locally and staged remotely before the first server changes. If an object is missing locally, reconciliation first attempts to recover it from a target server that retains the verified digest. If no verified copy can be recovered, preflight fails and leaves every `current` pointer unchanged.

## Protection and retention
A slot has EXACTLY ONE retention policy, owned by the slot itself: the policy of the slot's OWNING VARIANT (the variant file whose `[[slots]]` entry declares the slot). Targets carry rollout behavior only — there is NO per-target retention policy and NO union: retention belongs to the slot alone, so changing a slot's target membership (or its rollout groups) never changes its retention. Retention is evaluated per server because servers may have different release and variant histories. A successful deployment is committed back to each server before retention, allowing its generation history to record the deployment ID. Retention does not run if those commit markers cannot be reconciled.

Every generation record (`generations/<gen>/assignment.json`) and commit marker carries the target that created it (the originating target; legacy records written before this attribution existed carry none) — but retention no longer consults attribution: the slot's single owning-variant policy is applied to ALL of the server's generation records, and a tree object is swept only when that one policy does not retain it. Membership is never a retention input.

Capacity preflight reserves the larger of `capacity.reserve_bytes` and `capacity.reserve_percent` of the destination filesystem's TOTAL size after the upload (the percent is a percentage of the filesystem's total bytes, not of the currently available space). Capacity is a per-server policy declared on the server entry (`capacity = { reserve_bytes = ..., reserve_percent = ... }`) and resolved from the caller's CURRENT configuration on every push — HEAD and historical alike, because servers have no per-release history; it is never part of a release snapshot. The check may invoke the same protected retention before staging, but never weakens the retained set merely to make a deployment fit.

For each server, the retained content set is exactly this union:

```text
- the artifact referenced by the current generation
- the prior distinct successful artifact when protect_previous is true
- releases selected by durable pins
- the newest keep_distinct_artifacts distinct successful artifact bindings
- artifacts successfully activated less than keep_days ago
- that server's artifacts in the newest protect_deployments commits
```

An artifact binding is `(release ID, variant, tree digest)`. Repeated repair or restart generations for the same binding consume one retention slot, not many.

Pins are controller-side configuration (top-level `[[pins]]` entries in the project file), never server-stored state. The controller evaluates them from its local store when computing each server's retained set (`retention::compute_retained`); servers hold no pin records and never learn them remotely.
Distinct artifacts are ordered by their most recent successful activation. `keep_distinct_artifacts` and `keep_days` are union rules, not conditions that must both match. Age is measured from the binding's most recent successful activation rather than release creation time.

Retention is a mark-and-sweep operation under the remote mutation lock:
1. `status()` validates the complete `current` layout (current → generation → assignment.json → generation id); a missing or corrupt live assignment fails closed with an integrity error BEFORE any sweep decision — the tree behind an unreadable `current` is never deleted, because nothing is ever swept.
2. Mark tree objects referenced by the retained artifact bindings (the union above, computed over the server's generation inventory under the slot's single policy, plus the durable pins).
3. Keep generation, release, and commit metadata by default; metadata is small and continues to explain unavailable historical states.
4. Delete a tree object only when no retained binding or applicable pin on that server references it. A release or generation record may continue to describe a tree that is no longer installed and must report it as unavailable.
5. Remove abandoned operation-specific incoming directories — every `incoming/<deployment-id>/` directory EXCEPT the current deployment's active one, which stays for the in-flight operation.

The local store is NEVER swept by the receiver-side retention: the only LOCAL artifact deletion path is the checkpoint's global reachability garbage collection (see "Checkpoint and garbage collection"). Successful snapshot metadata may be kept indefinitely, but only entries inside the configured protection windows retain release and tree content. An older snapshot entry whose content was rotated remains auditable but is reported as unavailable for rollback. A local tree object is deleted only after no retained ledger, observed state, deployment record, or pin requires it — never out from under a known remote inventory; a tree that is missing locally is always recovered from a retaining server.

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
post-commit rule covers the observed refresh (which runs right after the terminal status
transition, before retention): every store operation there — `write_server` (the per-server
record) and `write_slot_observed` (each slot's ONE physical observed record) — is non-fatal maintenance,
surfaced as a warning, and a store fault never turns a committed push into an error. The observed records are
projections of already-durable facts, so no debt marker is needed: the next real push — or no-op —
re-projects them from current state, and retries converge without duplicate history.

Retention may later be exposed as an explicit maintenance command without changing these safety rules.

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
The initial transport is SSH with strict host-key verification (per-server `known_hosts` or pinned `host_key_fingerprint` — exactly one source per SSH server, enforced at config validation and re-checked defensively at transport construction). A `local` server address instead selects the pathless LOCAL connection kind, whose transport is rooted at the referencing slot's deploy_dir — the one authoritative physical root (there is no server-side endpoint to parse or compare, so the config graph cannot accept a local server whose root diverges from a slot's deploy_dir; construction and transport creation are equivalent, verified by the graph proptest). It exists for tests and for local targets. Server IDs, target names, variant names, release IDs, and paths are validated data and are never concatenated into remote shell commands. Bulk tree transfer is a plain bounded ssh stdin channel: each file's bytes are piped to a remote `cat > <path>` command (the target path is shell-quoted, so a path can never smuggle shell metacharacters out of the forced namespace), never a framed binary protocol. Every ssh operation runs through ONE bounded subprocess runner: every `ssh` connection carries `-o ConnectTimeout=10`, which bounds only the CONNECTION phase, and the runner imposes a hard deadline on the whole operation AFTER connection establishment — so nothing is unbounded. The `ssh-keyscan` key-pin step keeps the 10-second bound (native `-T` plus the runner's process-level deadline); every remote command and upload gets a distinct 60-second default (`SSH_COMMAND_TIMEOUT_SECS`: slower than connection establishment, which a slow-but-healthy remote legitimately needs, but bounded so a hung remote cannot stall the push); `exec` keeps its caller-supplied timeout. On deadline the runner KILLS the child (SIGKILL) and then deterministically REAPS it (joins the wait thread that owns the child) before returning a Timeout — an unreachable or dead host fails fast, no operation can hang the transport indefinitely, and no child is ever left uncollected (no kill-vs-wait race, no zombies, no return-before-reap). The stdin payload is written inside the same bounded wait: a >pipe-buffer upload to a remote that stops reading blocks the write, the deadline fires, and the kill closes the pipe (EPIPE, SIGPIPE ignored). A stdin-write failure follows the same rule as the deadline — the wait closure SAVES the write error, always drains and collects the child (`wait_with_output`), and only then returns the saved error — so a timed-out or write-failed upload is killed AND reaped, never an un-collected child (no return-before-reap on the write-error path either).

A small versioned remote helper owns status inspection, locking, object publication, generation switching, transaction-record keeping, adapter invocation, and retention. Client and helper perform a protocol-version handshake before mutation (the negotiated version is recorded under `control/`; schema version 1 speaks protocol 1). Every mutating request carries an operation ID and is idempotent, and each operation's durable per-server transaction record (`transactions/<operation-id>.json`, advanced `prepared` → `committed`/`compensated` by the helper) is written on every mutation. Two items here are PLANNED, not yet implemented: (a) reading those transaction records back so a disconnected client can reconnect and learn whether the operation prepared, committed, compensated, or never began — records are written, but nothing reconciles them on reconnect (unfinished-attempt recovery is driven by the controller's local records — the target's ledger, whose durable intent lines and reconciling finalizer carry the attempt — on the next push); and (b) packaging these operations as a single versioned helper binary uploaded beneath each slot's `deploy_dir` — the planned evolution. Neither changes this contract.

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

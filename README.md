# deploy

A small deployment tool with a Git-push-style interface:

```sh
deploy push production
```

Configure a named target once, then push your local files to every server in
that target with one command. Each server gets an immutable release stored
under each deployment slot's `deploy_dir`, activation is atomic per server (an atomically
swapped `current` symlink), verification runs after activation, and old
artifacts are rotated automatically.

> The command line is the authoritative documentation. `deploy --help`,
> `deploy help <command>`, and `deploy <command> --help` teach the project
> structure, every flag, and copy-paste-runnable examples. This file is the
> quick orientation; `requirement.md` has the full design.

## Install

Requires [Rust](https://rustup.rs). Build and install from this repository:

```sh
cargo install --path .
```

## Quick start: `deploy init`

Scaffold a fresh, immediately-pushable project:

```sh
deploy init my-app
cd my-app
```

`deploy init` is **local-first**: the server address defaults to
`local://<project>/.deploy-remote`, a local filesystem endpoint, so
`deploy push production` works end-to-end with nothing but this binary — no
SSH, no server, no provisioning. It never clobbers: re-running against a
project that already has `deploy.toml` (or a `releases/` tree) fails.

What it generates (also visible in `deploy init --help`):

```text
my-app/
  deploy.toml                          # schema v1: one server, target `production` (rollout only)
  releases/v1/standard.toml            # the `standard` variant (mappings + its slot + policies)
  releases/v1/systemd.toml             # example `systemd` activation variant with a real unit
  releases/v1/artifacts/build/output/app/hello   # placeholder artifact source
  releases/v1/artifacts/systemd/example.service  # the unit shipped by the systemd variant
  .deploy-remote/                      # local deployment endpoint (git-ignored)
```

Slots are declared INSIDE the variant files: `releases/v1/standard.toml`
carries the project's one slot (`app-1` → `server-01`, bound to the
`production` target by its `targets` list — targets derive their member slots
from the slots, they do not list them).

The generated files are typed TOML serialized from the same config structs
`Config::load` parses into — not formatted strings. `deploy init` validates
the flags before creating anything, re-loads the written project through the
strict loader, and removes the scaffold if that load fails: a reported
success always means the generated project is valid.

Then deploy:

```sh
deploy push production --dry-run   # preview the plan; touches nothing
deploy push production             # deploy (status: Successful; rollback payload keyed by deployment id)
deploy status production           # what is actually running on each server
deploy log production              # deployment history (each line prefixed with the rollback deployment id)
```

To retain a bounded history, establish a checkpoint once the rollout is
confirmed — see [Checkpoints (history floors)](#checkpoints-history-floors)
below.

To deploy to a real server instead of the local endpoint, either pass flags at
scaffold time:

```sh
deploy init my-app \
  --address app.example.com --user deploy \
  --host-key-fingerprint SHA256:...          # or --known-hosts /etc/ssh/known_hosts
```

or edit `deploy.toml` afterwards (it is annotated with exactly what to change).
SSH always uses strict host-key checking — trust-on-first-use is refused. Every
SSH server must configure EXACTLY ONE host-identity source: a dedicated
`known_hosts` file (an absolute path) or a pre-verified `host_key_fingerprint`
(`SHA256:...`); configuring both is ambiguous and rejected, and `local://`
addresses need neither.

## Commands

| Command | What it does |
| --- | --- |
| `deploy init [PATH]` | Scaffold a fresh project (see above). |
| `deploy push <target> [ref]` | Deploy local files (or restore a ref) to every server in the target, in rollout batches. |
| `deploy log <target>` | Deployment history — successful *and* failed attempts, each line prefixed with the rollback deployment id it produced (`-` for attempts with no snapshot). The visible history is the retained suffix when a checkpoint has been established. |
| `deploy status <target>` | What is actually running on each server right now (generation, release, variant, tree). |
| `deploy checkpoint <target> <deployment-id>` | Establish a monotonic HISTORY FLOOR at a successful deployment, then compact the history and run best-effort local artifact garbage collection (irreversible — requires `--yes`; `--dry-run` previews the discard list). |

Global flag: `--config <path>` selects a different `deploy.toml` than
`./deploy.toml` (usable anywhere on the command line).

### Push and rollback references

```sh
deploy push production --dry-run                 # preview; touches nothing
# HEAD: the local files (default — `@` and `HEAD` mean the same)
deploy push production
# jj-style references: the target is passed ONCE, never repeated in the
# reference; every relative form resolves against the target argument.
deploy push production @-              # roll back to the PREVIOUS successful deployment
deploy push production @--             # two deployments back (the grandparent)
# parent(...) forms contain a comma — the shell splits them at the space, so
# quote them on the command line:
deploy push production 'parent(@, 3)'    # three deployments back from the latest
# DIRECT release deploy: the named release to the CURRENT target's slots,
# from the release's OWN stored slot snapshot — no history needed, cross-
# target capable (release:<id>; the refid forms below are snapshot ancestry).
# The target's CURRENT slot membership must exactly match the slot set the
# release froze for it; a drifted membership is rejected before remote access.
deploy push production release:rel-sha256-41da2f63a950
# deployment-id refs resolve to EXACT stored states, then step N ancestors
# (N = 0 is the deployment itself; positions are DERIVED from the log order):
deploy push production deploy-20260821T102000Z              # EXACT stored state of that deployment
deploy push production deploy-20260821T102000Z--            # two deployments before it
deploy push production 'parent(deploy-20260821T102000Z, 1)'   # one deployment before it
```

ROLLBACK PAYLOADS ARE KEYED BY DEPLOYMENT ID: `@`, `@-`, `@--`, and
`parent(...)` walk the target's DEPLOYMENT HISTORY — the snapshot log in
deployment order (each successful deployment IS a rollback payload keyed by
its id; failed and degraded attempts never resolve). The old `sN`
snapshot-index forms (`sN`, `sN-`, `sN--`, `parent(sN, M)`) and the
release-refid ancestor forms are REMOVED — migrate `sN` to the deployment id
of that snapshot's deployment (`deploy log` shows it), and reference a
release only via `release:<id>`.

- Every *successful* deployment appends a snapshot KEYED BY ITS DEPLOYMENT
  ID; `deploy push <target> <deployment-id>` restores exactly that
  deployment's stored state; failed and degraded attempts never advance the
  rollback ref and cannot be rolled back to.
- A refid is a deployment id (`deploy-...`). It resolves to THAT deployment's
  stored rollback payload, then walks the ancestor steps (N positions back in
  the deployment history — positions are derived, never stored).
- `release:<id>` is the DIRECT release form (shell-safe, no slash): deploy
  the named release to the current target's slots from the release's OWN
  stored slot-variant snapshot — no deployment-history stepping, no
  deployment-snapshot exact-binding checks, and no target snapshot history
  required (the release may be built/pushed anywhere; a fresh target
  deploys directly). The target's CURRENT slot membership must EXACTLY
  equal the slot set the release record froze for it (derived from the
  record's per-variant canonical slots whose `targets` contain the target):
  membership drift — a slot added, removed, or renamed since the release
  was built — is rejected at plan time, before any remote access, and
  physical bindings (server / `deploy_dir`) are intentionally allowed to
  differ.
- Out-of-range refs fail closed before anything runs: an empty chain, a
  missing deployment id, or walking past the start of the chain is a ref
  error — never an underflow or a guess.
- Pushing identical content prints `Everything up to date`.
- Rollout is batched per `rollout.batch_size`; on a failed server, earlier
  batches roll back by default (`failure_policy: rollback_changed`). The final
  status is reported explicitly, including partial states like `degraded`.

## Checkpoints (history floors)

A checkpoint models the target's retained history as a monotonic FLOOR, not
another deployment or snapshot. Once you checkpoint a successful deployment,
the retained history starts at that attempt, the checkpoint deployment's
snapshot becomes the OLDEST rollback state, and everything strictly before
it — older snapshots, older attempts (failed attempts included), and their
`deployments/<id>/` directories — is discarded. The checkpoint deployment
and everything after it is kept.

```sh
deploy checkpoint production deploy-20260821T102000Z --dry-run   # preview the discard list; touches nothing
# would discard 3 snapshots: deploy-... (the deployments before the checkpoint)
# would discard 4 attempts: deploy-...
# would delete 4 deployment directories: ...
deploy checkpoint production deploy-20260821T102000Z --yes       # establish the floor (IRREVERSIBLE)
deploy log production       # now shows only the retained suffix
deploy push production deploy-20260821T102000Z   # the checkpoint deployment stays the oldest rollback
```

- The deployment id is an explicit, REQUIRED argument (the operation is
  irreversible) and `--yes` is required for the real operation; without
  `--yes` and without `--dry-run` the command is refused up front.
- The deployment must be a SUCCESSFUL deployment of the target (it must have
  produced a snapshot); otherwise the checkpoint fails with
  `checkpoint requires a successful deployment`.
- A checkpoint does NOT deploy anything, does NOT contact remote servers, and
  does NOT create another snapshot. The checkpoint deployment's existing
  snapshot remains the actual rollback state.
- The floor is stored as a small marker at
  `targets/<target>/refs/history-floor.json` (not another state snapshot),
  written durably BEFORE the physical compaction rewrites the logs and
  deletes the below-floor deployment directories. Because every read path is
  gated by the marker, an interrupted cleanup can never expose history below
  the durable floor.
- Repeating the same checkpoint is idempotent (a no-op); advancing it to a
  LATER deployment updates the floor; a checkpoint can NEVER move backward —
  an earlier deployment than the current floor is refused.
- Advancing the floor is TRANSACTIONAL: the current floor is moved aside to
  a durable, transaction-tagged backup
  (`targets/<target>/refs/history-floor.json.prev.<target-id>`), and any
  failure before the replacement's commit point restores the previous floor
  (rename back + parent fsync) — a failed advance can never erase the
  previously durable floor. If the restore itself ALSO fails (a torn
  advance: the marker absent, the validated backup still holding the
  previous floor), every read returns the backup's floor — never "no
  floor" — and the NEXT checkpoint repairs the torn state AUTOMATICALLY by
  restoring the validated backup (rename + parent fsync): recovery
  restores, never deletes, the only valid floor.
- The checkpoint ALSO runs LOCAL HISTORY COMPACTION + ARTIFACT GARBAGE
  COLLECTION as its post-commit best-effort maintenance, reported as four
  distinguishable outcomes: (a) the logical checkpoint is established
  (the durable floor); (b) the history files are compacted (the below-floor
  `deployments/<id>/` directories deleted and `attempts.jsonl` /
  `snapshots.jsonl` rewritten to the retained suffix); (c) artifact garbage
  collection completed — a GLOBAL, reachability-based pass that unlinks the
  release records (`releases/<release-id>/`) and tree objects
  (`objects/sha256/<digest>/`) no longer reachable from any target's
  retained history, any retained deployment record (unfinished operations
  included), any target's current observed artifact, or any configured pin;
  (d) cleanup incomplete and retry required — a post-commit maintenance
  failure never moves or removes the established floor and never deletes
  anything in the retained set, the report says so explicitly, and
  re-running the same checkpoint converges. Reachability is recomputed from
  the whole store on every run: there is no persisted deletion worklist.
- PINS (`<store>/pins.json`) retain ARTIFACT CONTENT ONLY. A pin — by
  release id (marks every variant/tree in that release record) or by exact
  binding `(release, variant, tree)` — protects the release record and tree
  object from the garbage collector, but it NEVER keeps an old deployment,
  attempt, or snapshot in history: the floor-gated reads stay keyed on the
  history floor, so a pinned pre-floor artifact's bytes survive while its
  history stays discarded. These store-level pins are the checkpoint GC's
  anchors, distinct from the rotation subsystem's project-file `[[pins]]`
  (which protect the remote rotation retained set; the checkpoint flow is
  store-only and never loads `deploy.toml`).
- "Disk cleanup" means unlinking unreachable files/directories and syncing
  the affected directories so filesystem space can be reclaimed — NOT secure
  physical erasure: SSD firmware, copy-on-write filesystems, snapshots,
  journals, and backups may retain old blocks. The checkpoint never contacts
  servers; remote artifact cleanup remains rotation's responsibility.
- Checkpointing one target never changes another target's history: the
  floor, compaction, and cleanup are per-target for history and global only
  for the shared artifact store (where another target's references protect
  shared content).

## Project structure (forced)

```text
deploy.toml                    # names the active release, servers, and targets (rollout only)
releases/<name>/              # the release directory named by `release:`
releases/<name>/<variant>.toml  # every *.toml file here is a variant (file stem = name);
                                # each variant declares its own [[slots]] (server, deploy_dir, targets)
releases/<name>/artifacts/    # artifact sources referenced by variant mappings
```

- A **release** is a directory under `releases/`. `deploy.toml` names the
  active one with `release: <name>`.
- A **variant** is a `*.toml` file directly inside the release directory,
  named by its file stem. It owns its artifact mappings, its deployment
  policies (activation, verification), and its deployment **slots**: the
  `[[slots]]` entries of the file are the slot declarations, and the declaring
  file IS the slot's variant binding. Capacity is a per-server policy declared
  on the server entry.
- A **deployment slot** binds one server to one workload under an ID, names the
  absolute `deploy_dir` on the server, and declares the targets it belongs to
  (`targets = ["..."]`). A slot may be a member of several targets, and two
  slots may share one server in different targets, but within a single target
  each server appears at most once. A **target** carries ROLLOUT behavior
  only; its member slots are DERIVED from the slots' `targets` lists —
  targets do not list their slots.
- Retention (`rotation`) belongs to the SLOT, not the target: the variant
  file that declares the slot owns its one retention policy, so a slot shared
  across several targets keeps exactly one policy and membership changes never
  change retention.

## Config reference (condensed)

```toml
schema_version = 1
application = "my-app"
release = "v1"               # active release dir under releases/

[[servers]]                  # declared once; slots reference by id
id = "server-01"             # durable ID; never rename it
address = "local:///abs/path"   # or a hostname for SSH
user = "deploy"
capacity = { reserve_bytes = 0, reserve_percent = 0 }  # per-server headroom, zero by default
# port = 22
# SSH addresses need EXACTLY ONE host-identity source (trust-on-first-use is disabled):
# known_hosts = "/etc/ssh/known_hosts"   # absolute path
# host_key_fingerprint = "SHA256:..."    # pre-verified fingerprint; both together are rejected

[targets.production]         # targets carry ROLLOUT only: their member slots
rollout = { batch_size = 1, stop_on_failure = true, failure_policy = "rollback_changed" }
                            # are derived from the slots' `targets` lists
```

A variant file (`releases/<release>/<name>.toml`) is a mapping plus policy —
plus the variant's deployment slots and its slot-owned retention policy:

```toml
description = "Standard deployment"

# This variant's deployment slots: one slot = one server + this variant, under
# an ID, with an absolute deploy_dir, belonging to one or more targets (targets
# derive their members from these declarations).
[[slots]]
id = "app-1"
server = "server-01"
targets = ["production"]
deploy_dir = "/srv/deploy/my-app"   # absolute path on the server

[[artifact.mappings]]
from = "artifacts/build/output/"   # relative to the release directory
to = "app/"
recursive = true
# conflict = "error"                (strict semantics: collisions always error —
#                                    overlapping destinations are rejected up front)
# mode = "0755"                              (or "preserve")

[activation]
adapter = "none"                # pure file push; for per-deployment service management:
                                # adapter = "systemd", scope = "user" | "system", reconcile_managed_units = true,
                                # and one or more [[activation.units]] {name, artifact_path, enable, restart}.
                                # "system" scope needs an admin-installed root-owned wrapper unit; artifact
                                # unit files are never linked into /etc/systemd/system.

[verification]
adapter = "command"
argv = ["{{ deploy_dir }}/current/app/server", "health-check"]  # rendered per slot before exec
timeout_seconds = 5
attempts = 1
interval_seconds = 0

[rotation.per_server]         # SLOT-OWNED retention (the slot's one policy;
keep_distinct_artifacts = 5   # targets carry rollout only, so membership
keep_days = 14                # changes never change retention)
protect_previous = true

[rotation.deployment]
protect_deployments = 2
```

`argv` (and, for the systemd adapter, unit-file content) is rendered through a
strict Jinja-style template module with a fixed set of elected variables
before anything is executed: `{{ deploy_dir }}` (the slot's absolute on-server
directory), `{{ variant }}`, `{{ application }}`, `{{ release }}` (the
immutable `ReleaseId` of the artifact actually being deployed, e.g.
`rel-sha256-…` — never the caller's current release name), `{{ target }}`,
`{{ server }}`. Only these names are recognized — no
expressions, filters, or control flow; an unknown or malformed template fails
the push loudly. Mapping `from` paths use only `{{ variant }}` (trees are
content-addressed and shared across slots), while activation/verification
render with the full slot context.

A complete `adapter = "systemd"` variant with a real, copy-paste-usable unit
file ships in `tests/fixtures/quickstart/releases/v1/systemd.toml` (and is
scaffolded by `deploy init` as `releases/v1/systemd.toml`). The unit file is
rendered per slot at activation time (`ExecStart={{ deploy_dir }}/current/app/server`),
so the tree itself stays slot-independent.

Capacity headroom is a per-server policy, not a variant one: it lives on the
`[[servers]]` entry (`capacity = { reserve_bytes = ..., reserve_percent = ... }`,
zero by default), is shared by every deployment slot on that server, and is
resolved from this file at preflight time — it is never part of a release.

Validation is strict: `deploy_dir` and `known_hosts` must be absolute paths,
server/slot IDs must be unique (slot IDs across every variant's slots), each
slot's server must be a declared `[[servers]]` entry, every target in a slot's
`targets` list must be a declared `[targets.<name>]` key (and the list must
not be empty), and each target must have at least one member slot. Every
SSH-shaped server address must configure
EXACTLY ONE of `known_hosts` or `host_key_fingerprint` (neither means
trust-on-first-use, which is refused; both are ambiguous) — `local://`
addresses are exempt. A config that fails validation is rejected at load time,
before anything is touched.

## Maintenance

- **Add a variant**: add `releases/<release>/<new-name>.toml`; declare its
  slots in the file itself.
- **Add a server**: add a `[[servers]]` entry to `deploy.toml`, then a
  `[[slots]]` entry inside the variant file that owns the workload (server,
  absolute `deploy_dir`, `target`).
- **Add a slot to a target**: the slot's `targets` list is the membership —
  add the target's name to it (a slot may belong to several targets); targets
  do not list slots.
- **Cut a release**: copy the release directory (e.g. `releases/v1` →
  `releases/v2`), edit the variant files (new mappings, verification, etc.),
  and set `release = "v2"` in `deploy.toml`. Old releases stay deployable
  via the direct `release:<id>` form (or the release-refid form
  `parent(<release-id>, 0)` for snapshot ancestry).
- **Roll back**: `deploy push production @-` restores the previous
  successful snapshot; `deploy push production 'parent(@, 3)'` the 3rd
  previous. Historical deployments restore their original behavior — they
  never re-run today's verification or activation settings.
- **Change rollout policy**: edit `[targets.<name>]` in `deploy.toml`; push.

## Requirements on servers (SSH)

- SSH access as the configured `user` with strict host-key checking.
- The deployment account must be able to create each slot's `deploy_dir`
  (e.g. `/srv/deploy/my-app`) — provision it once if not.

## Where things live locally

State is kept under `~/.local/share/simple-deploy/<application>/` (or
`$XDG_DATA_HOME`): immutable tree objects, release records, per-target history,
and the refs used for rollback. Treat anything you map into the artifact as
confidential — it is retained in multiple versions locally and remotely.
Prefer external secret references over mapping secret files into the artifact.

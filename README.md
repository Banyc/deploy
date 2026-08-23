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
  deploy.toml                          # schema v1: one server, target `production` (rollout+rotation)
  releases/v1/standard.toml            # the `standard` variant (mappings + its slot + policies)
  releases/v1/systemd.toml             # example `systemd` activation variant with a real unit
  releases/v1/artifacts/build/output/app/hello   # placeholder artifact source
  releases/v1/artifacts/systemd/example.service  # the unit shipped by the systemd variant
  .deploy-remote/                      # local deployment endpoint (git-ignored)
```

Slots are declared INSIDE the variant files: `releases/v1/standard.toml`
carries the project's one slot (`app-1` → `server-01`, bound to the
`production` target by its `target` field — targets derive their member slots
from the slots, they do not list them).

The generated files are typed TOML serialized from the same config structs
`Config::load` parses into — not formatted strings. `deploy init` validates
the flags before creating anything, re-loads the written project through the
strict loader, and removes the scaffold if that load fails: a reported
success always means the generated project is valid.

Then deploy:

```sh
deploy push production --dry-run   # preview the plan; touches nothing
deploy push production             # deploy (status: Successful, ref production@f0)
deploy status production           # what is actually running on each server
deploy log production              # deployment history
```

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
| `deploy log <target>` | Deployment history — successful *and* failed attempts. |
| `deploy status <target>` | What is actually running on each server right now (generation, release, variant, tree). |

Global flag: `--config <path>` selects a different `deploy.toml` than
`./deploy.toml` (usable anywhere on the command line).

### Push and rollback references

```sh
deploy push production --dry-run                 # preview; touches nothing
# HEAD: the local files
deploy push production
# roll back to the 2nd successful deployment (restores the exact historical
# per-slot artifacts — variant and tree together)
deploy push production production@f1
deploy push production production@f1:current    # same release, but keep each server's configured variant
deploy push production release/rel-41da2f63      # deploy a specific retained release
# same release, but assign each current server its CONFIGURED variant
# (the tree still comes from the release's own per-variant bindings)
deploy push production release/rel-41da2f63:current
```

- `<target>@fN` refers to the Nth *successful* fleet snapshot; failed and
  degraded attempts never advance the rollback ref and cannot be rolled back
  to (`deploy log` still shows them).
- The `:current` suffix — on `release/<id>:current` or `<target>@fN:current` —
  keeps each slot's CURRENT configured variant (the variant file that declares
  the slot in today's config) while the tree still comes from the referenced
  release's own per-variant bindings. The bare form (`release/<id>`,
  `<target>@fN`) instead restores the release/snapshot's OWN stored
  slot→variant mapping. A `:current` push fails closed if the referenced
  release does not ship the current variant (e.g. the variant was renamed
  after the release was materialized).
- Pushing identical content prints `Everything up to date`.
- Rollout is batched per `rollout.batch_size`; on a failed server, earlier
  batches roll back by default (`failure_policy: rollback_changed`). The final
  status is reported explicitly, including partial states like `degraded`.

## Project structure (forced)

```text
deploy.toml                    # names the active release, servers, and targets (rollout + rotation)
releases/<name>/              # the release directory named by `release:`
releases/<name>/<variant>.toml  # every *.toml file here is a variant (file stem = name);
                                # each variant declares its own [[slots]] (server, deploy_dir, target)
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
  absolute `deploy_dir` on the server, and declares the ONE target it belongs
  to (`target = "..."`). A **target** carries the rollout and rotation policy;
  its member slots are DERIVED from the slots' `target` fields — targets do
  not list their slots.
- Retention (`rotation`) belongs to the target, not the variant.

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

[targets.production]         # targets carry rollout + rotation only: their member
rollout = { batch_size = 1, stop_on_failure = true, failure_policy = "rollback_changed" }
                            # slots are derived from the slots' `target` fields

[targets.production.rotation.per_server]   # retention is per target
keep_distinct_artifacts = 5
keep_days = 14
protect_previous = true
```

A variant file (`releases/<release>/<name>.toml`) is a mapping plus policy —
plus the variant's deployment slots:

```toml
description = "Standard deployment"

# This variant's deployment slots: one slot = one server + this variant, under
# an ID, with an absolute deploy_dir, belonging to exactly ONE target (targets
# derive their members from these declarations).
[[slots]]
id = "app-1"
server = "server-01"
target = "production"
deploy_dir = "/srv/deploy/my-app"   # absolute path on the server

[[artifact.mappings]]
from = "artifacts/build/output/"   # relative to the release directory
to = "app/"
recursive = true
# conflict = "error" | "replace" | "keep"     (default "error")
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
slot's server must be a declared `[[servers]]` entry, each slot's `target`
must be a declared `[targets.<name>]` key, and each target must have at least
one member slot. Every SSH-shaped server address must configure
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
- **Add a slot to a target**: the slot's `target` field is the membership —
  set it (and only it) to the target's name; targets do not list slots.
- **Cut a release**: copy the release directory (e.g. `releases/v1` →
  `releases/v2`), edit the variant files (new mappings, verification, etc.),
  and set `release = "v2"` in `deploy.toml`. Old releases stay deployable via
  their `release/<id>` refs.
- **Roll back**: `deploy push production production@fN` restores a historical
  successful fleet snapshot; `deploy push production release/<id>` deploys a
  retained release. Historical deployments restore their original behavior —
  they never re-run today's verification or activation settings.
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

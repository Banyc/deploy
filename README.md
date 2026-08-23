# deploy

A small deployment tool with a Git-push-style interface:

```sh
deploy push production
```

Configure a named target once, then push your local files to every server in
that target with one command. Each server gets an immutable release stored
under each pod's `deploy_dir`, activation is atomic per server (an atomically swapped
`current` symlink), verification runs after activation, and old artifacts are
rotated automatically.

## Install

Requires [Rust](https://rustup.rs). Build and install from this repository:

```sh
cargo install --path .
```

## Quick start

Your project needs a `deploy.toml` plus a release directory containing the
variant files and the artifact sources they map:

```text
my-project/
  deploy.toml
  releases/
    v1/
      standard.toml        # the "standard" variant: mappings + policies
      artifacts/
        build/output/app/server
```

`deploy.toml` names the active release, declares every server once at the top
level, binds each server to a variant with a pod, and groups pods into targets
by ID:

```toml
schema_version = 1
application = "example"

# The active release. The project structure is forced: the release directory
# is `releases/<name>/`, and every `*.toml` file inside it is a variant
# (e.g. `standard`); artifact sources live beneath its `artifacts/` tree.
release = "v1"

# Servers are declared once; a pod binds one server to one variant, and
# targets reference pods by ID.
[[servers]]
id = "server-01"            # durable ID; never rename it
address = "server-01.example.com"
user = "deploy"

[[servers]]
id = "server-02"
address = "server-02.example.com"
user = "deploy"

[[pods]]
id = "app-1"
server = "server-01"
variant = "standard"
deploy_dir = "/srv/deploy/example"

[[pods]]
id = "app-2"
server = "server-02"
variant = "standard"
deploy_dir = "/srv/deploy/example"

[targets.production]
rollout = { batch_size = 1, stop_on_failure = true, failure_policy = "rollback_changed" }
pods = ["app-1", "app-2"]

# Retention belongs to the target: how aggressively its servers rotate.
[targets.production.rotation.per_server]
keep_distinct_artifacts = 5   # keep the newest 5 distinct artifacts per server
keep_days = 14                # ...and everything activated in the last 14 days
protect_previous = true       # never delete the artifact `current` can roll back to

[targets.production.rotation.fleet]
protect_deployments = 2       # keep each server's artifacts of the newest 2 successful deployments
```

Each variant is a `*.toml` file directly inside the release directory, named by
its file stem. It owns its artifact mappings and deployment policies
(activation, verification, capacity); retention (`rotation`) belongs to each
target. `from` paths resolve inside the release
directory, so artifact sources live under `releases/v1/artifacts/`:

```toml
# The `standard` variant: its artifact mappings plus deployment policies.
# `from` paths resolve inside the release directory (`releases/<name>/` — the
# project structure is forced), so artifact sources live under
# `releases/v1/artifacts/`. Rotation is not a variant setting: it belongs to
# the target.
description = "Standard deployment"

[[artifact.mappings]]
from = "artifacts/build/output/"
to = "app/"
recursive = true

[activation]
adapter = "none"          # or: systemd (scope = "user")

[verification]
adapter = "command"
argv = ["/srv/deploy/example/current/app/server", "health-check"]
timeout_seconds = 15
attempts = 3
interval_seconds = 2

[capacity]
reserve_bytes = 1073741824   # keep at least 1 GiB free on servers
reserve_percent = 0
```

Then deploy:

```sh
deploy push production
```

To cut a new release, copy the release directory (e.g. `releases/v2`), set
`release = "v2"` in `deploy.toml`, and edit its variant files.

## Commands

### `deploy push <target> [reference]`

Deploy to a target. Without a reference it deploys the currently mapped local
files (`HEAD`). Pushing identical content prints `Everything up to date`.

Useful flags and references:

```sh
deploy push production --dry-run                 # show what would change, touch nothing
deploy push production production@f1             # roll back to the 2nd-to-last successful deployment
deploy push production release/rel-41da2f63      # deploy a specific retained release
```

Rollout is batched per `rollout.batch_size`. If activation or verification
fails on a server, earlier batches are rolled back by default
(`failure_policy: rollback_changed`); failed attempts never advance
`refs/last-successful`. The final status is reported explicitly — including
partial states like `degraded` — with the actual generation on every server.

### `deploy log <target>`

Show the target's deployment history (successful *and* failed attempts).

### `deploy status <target>`

Show what is actually running on each server right now: generation, release,
variant, and tree digest.

Global flag: `--config <path>` to use a different config file than
`./deploy.toml`.

## How mappings work

Each variant file maps local files into the artifact tree:

```toml
# inside releases/v1/standard.toml
[[artifact.mappings]]
from = "artifacts/build/output/"          # relative to the release directory
to = "app/"
recursive = true
conflict = "replace"                        # "error" | "replace" | "keep"
mode = "0755"                               # optional explicit mode
```

- Mappings apply in declaration order; collisions fail unless you set
  `conflict`.
- `{{ variant }}` is the only template variable, so all servers assigned the
  same variant always receive identical content.
- `from` paths resolve inside the release directory (`artifacts/` is the
  convention); absolute paths and `..` escapes are rejected.

## Variants

Every `*.toml` file directly inside the release directory is a variant named by
its file stem — declaring a variant is adding a file. Assign one per server. A
typical use is a different build flavor for beefier machines:

```text
releases/
  v1/
    standard.toml
    high-capacity.toml
```

```toml
# deploy.toml — a pod binds one server to one variant
[[servers]]
id = "server-01"
address = "..."

[[servers]]
id = "server-03"
address = "..."

[[pods]]
id = "app-1"
server = "server-01"
variant = "standard"

[[pods]]
id = "hc-1"
server = "server-03"
variant = "high-capacity"

# the target groups pods by ID and sets the rollout policy
[targets.production]
rollout = { batch_size = 2, stop_on_failure = true, failure_policy = "rollback_changed" }
pods = ["app-1", "hc-1"]
```

A pod can be a member of several targets. Two pods may share one server in
different targets, but within a single target each server appears at most once
(one running generation per server).

Each variant file has the same shape as `standard.toml` in the Quick start —
its own mappings, activation, verification, and capacity. Retention
(`rotation`) belongs to the target: each target declares how aggressively its
own servers rotate, so a canary target can retain more than production.

## systemd support

Set `adapter: systemd` with `scope: user` in the variant file to have pushes
register, enable, and restart unit files that you map into the artifact (e.g.
`integration/systemd/example.service`):

```toml
# inside releases/v1/standard.toml
[activation]
adapter = "systemd"
scope = "user"
reconcile_managed_units = true

[[activation.units]]
name = "example.service"
artifact_path = "integration/systemd/example.service"
enable = true
restart = true
```

On rollback the previous generation's units are restored and verified.

## Requirements on servers

- SSH access as the configured `user` (strict host-key checking is used).
- The deployment account must be able to create each pod's `deploy_dir`
  (e.g. `/srv/deploy/example`) — provision it once if not.

## Where things live locally

State is kept under `~/.local/share/simple-deploy/<application>/`: immutable
tree objects, release records, per-target history, and refs used for
rollback. Treat anything you map into the artifact as confidential — it is
retained in multiple versions locally and remotely. Prefer external secret
references over mapping secret files into the artifact.

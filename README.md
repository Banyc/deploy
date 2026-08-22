# deploy

A small deployment tool with a Git-push-style interface:

```sh
deploy push production
```

Configure a named target once, then push your local files to every server in
that target with one command. Each server gets an immutable release stored
under `remote_root`, activation is atomic per server (an atomically swapped
`current` symlink), verification runs after activation, and old artifacts are
rotated automatically.

## Install

Requires [Rust](https://rustup.rs). Build and install from this repository:

```sh
cargo install --path .
```

## Quick start

Your project needs a `deploy.yaml` plus a release directory containing the
variant files and the artifact sources they map:

```text
my-project/
  deploy.yaml
  releases/
    v1/
      standard.yaml        # the "standard" variant: mappings + policies
      artifacts/
        build/output/app/server
```

`deploy.yaml` names the active release and declares the fleet:

<!-- fixture: tests/fixtures/quickstart/deploy.yaml -->
```yaml
schema_version: 1
application: example
remote_root: /srv/deploy/example

# The active release. The project structure is forced: the release directory
# is `releases/<name>/`, and every `*.yaml` file inside it is a variant
# (e.g. `standard`); artifact sources live beneath its `artifacts/` tree.
release: v1

targets:
  production:
    rollout:
      batch_size: 1
      stop_on_failure: true
      failure_policy: rollback_changed
    servers:
      - id: server-01            # durable ID; never rename it
        address: server-01.example.com
        user: deploy
        variant: standard
      - id: server-02
        address: server-02.example.com
        user: deploy
        variant: standard
```

Each variant is a `*.yaml` file directly inside the release directory, named by
its file stem. It owns its artifact mappings and deployment policies
(activation, verification, capacity, rotation). `from` paths resolve inside the
release directory, so artifact sources live under `releases/v1/artifacts/`:

<!-- fixture: tests/fixtures/quickstart/releases/v1/standard.yaml -->
```yaml
# The `standard` variant: its artifact mappings plus deployment policies.
# `from` paths resolve inside the release directory (`releases/<name>/` — the
# project structure is forced), so artifact sources live under
# `releases/v1/artifacts/`.
description: Standard deployment

artifact:
  mappings:
    - from: artifacts/build/output/
      to: app/
      recursive: true

activation:
  adapter: none          # or: systemd (scope: user)

verification:
  adapter: command
  argv:
    - /srv/deploy/example/current/app/server
    - health-check
  timeout_seconds: 15
  attempts: 3
  interval_seconds: 2

capacity:
  reserve_bytes: 1073741824   # keep at least 1 GiB free on servers

rotation:
  per_server:
    keep_distinct_artifacts: 5
    keep_days: 14
    protect_previous: true
```

These examples are checked against real fixture files under
`tests/fixtures/quickstart/`; a schema change that would invalidate them fails
the test suite.

Then deploy:

```sh
deploy push production
```

To cut a new release, copy the release directory (e.g. `releases/v2`), set
`release: v2` in `deploy.yaml`, and edit its variant files.

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
`./deploy.yaml`.

## How mappings work

Each variant file maps local files into the artifact tree:

```yaml
# inside releases/v1/standard.yaml
artifact:
  mappings:
    - from: artifacts/build/output/          # relative to the release directory
      to: app/
      recursive: true
      conflict: replace                        # error | replace | keep
      mode: "0755"                             # optional explicit mode
```

- Mappings apply in declaration order; collisions fail unless you set
  `conflict`.
- `{{ variant }}` is the only template variable, so all servers assigned the
  same variant always receive identical content.
- `from` paths resolve inside the release directory (`artifacts/` is the
  convention); absolute paths and `..` escapes are rejected.

## Variants

Every `*.yaml` file directly inside the release directory is a variant named by
its file stem — declaring a variant is adding a file. Assign one per server. A
typical use is a different build flavor for beefier machines:

```text
releases/
  v1/
    standard.yaml
    high-capacity.yaml
```

```yaml
# deploy.yaml — the target chooses which variant each server runs
targets:
  production:
    servers:
      - id: server-01
        address: ...
        variant: standard
      - id: server-03
        address: ...
        variant: high-capacity
```

Each variant file has the same shape as `standard.yaml` in the Quick start —
its own mappings, activation, verification, capacity, and rotation.

## systemd support

Set `adapter: systemd` with `scope: user` in the variant file to have pushes
register, enable, and restart unit files that you map into the artifact (e.g.
`integration/systemd/example.service`):

```yaml
# inside releases/v1/standard.yaml
activation:
  adapter: systemd
  scope: user
  reconcile_managed_units: true
  units:
    - name: example.service
      artifact_path: integration/systemd/example.service
      enable: true
      restart: true
```

On rollback the previous generation's units are restored and verified.

## Requirements on servers

- SSH access as the configured `user` (strict host-key checking is used).
- The deployment account must be able to create `remote_root`
  (e.g. `/srv/deploy/example`) — provision it once if not.

## Where things live locally

State is kept under `~/.local/share/simple-deploy/<application>/`: immutable
tree objects, release records, per-target history, and refs used for
rollback. Treat anything you map into the artifact as confidential — it is
retained in multiple versions locally and remotely. Prefer external secret
references over mapping secret files into the artifact.

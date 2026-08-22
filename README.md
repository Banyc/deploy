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

Your project needs one file, `deploy.yaml`, next to the files you want to ship:

```text
my-project/
  deploy.yaml
  build/
  deployment/
```

A minimal example that deploys two servers via SSH:

```yaml
schema_version: 1
application: example
remote_root: /srv/deploy/example

variants:
  standard: {}

artifact:
  mappings:
    - from: build/output/
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

Then deploy:

```sh
deploy push production
```

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

Each mapping copies local files into the artifact tree:

```yaml
artifact:
  mappings:
    - from: build/output/                      # relative to deploy.yaml
      to: app/
      recursive: true
      conflict: replace                        # error | replace | keep
      mode: "0755"                             # optional explicit mode
```

- Mappings apply in declaration order; collisions fail unless you set
  `conflict`.
- `{{ variant }}` is the only template variable, so all servers assigned the
  same variant always receive identical content.
- Sources must stay under the project root; absolute paths and `..` escapes
  are rejected.

## Variants

Declare any number of variants and assign them per server. A typical use is a
different build flavor for beefier machines:

```yaml
variants:
  standard: {}
  high-capacity: {}

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

## systemd support

Set `adapter: systemd` with `scope: user` to have pushes register, enable,
and restart unit files that you map into the artifact (e.g.
`integration/systemd/example.service`):

```yaml
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

# `devops`

A simple CLI tool to deploy Rust musl binaries.

## Commands

- `deploy`: `scp`, `ln -s`, and then `systemctl restart`.
- `systemctl`: Overwrite a systemd service file.

## Usage

1. Clone the repository
1. `cargo install --path .`
1. `devops --help`

## References

- Implementation: [A simple but safe deploy script](https://blog.wesleyac.com/posts/simple-deploy-script)

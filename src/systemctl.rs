use std::sync::Arc;

use clap::Args;
use xshell::{cmd, Shell};

/// Overwrite systemd service file.
#[derive(Debug, Args)]
pub struct SystemctlArgs {
    /// e.g.: `user@server-address`
    pub server_ssh: Arc<str>,
    /// e.g.: `"/path/to/remote/directory/"`
    pub server_path: Arc<str>,
    /// e.g.: `example`
    pub binary_name: Arc<str>,
    /// e.g.: `"-a -b c"`
    pub binary_args: Arc<str>,
    /// e.g.: `user`
    pub user: Arc<str>,
    /// e.g.: `group`
    pub group: Arc<str>,
}

pub fn systemctl(args: SystemctlArgs) -> Result<(), Box<dyn std::error::Error>> {
    let text = service_text(
        &args.server_path,
        &args.binary_name,
        &args.binary_args,
        &args.user,
        &args.group,
    );
    let text = std::dbg!(text);

    let binary_name = args.binary_name;
    let service_file_path = format!("/etc/systemd/user/{binary_name}.service");
    let write_file_cmd = format!(
        "rm -f {service_file_path}
        touch {service_file_path}
        echo '{text}' > {service_file_path}
        systemctl enable {service_file_path}"
    );

    let sh = Shell::new()?;
    let server_ssh = args.server_ssh.as_ref();
    cmd!(sh, "ssh -q -T {server_ssh} {write_file_cmd}").run()?;

    Ok(())
}

fn service_text(
    server_path: &str,
    binary_name: &str,
    binary_args: &str,
    user: &str,
    group: &str,
) -> String {
    format!(
        "[Unit]
Description={binary_name}
After=network.target

[Service]
ExecStart=/bin/sh -c {server_path}/{binary_name} {binary_args}
User={user}
Group={group}

[Install]
WantedBy=multi-user.target
"
    )
}

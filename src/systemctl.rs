use std::{io::Write, sync::Arc};

use clap::Args;
use tempfile::NamedTempFile;
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
    /// e.g.: `user`
    pub user: Arc<str>,
    /// e.g.: `group`
    pub group: Arc<str>,
    /// e.g.: `-- -a -b c`
    pub binary_args: Vec<Arc<str>>,
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
    let mut temp_file = NamedTempFile::new()?;
    temp_file.write_all(text.as_bytes())?;

    let binary_name = args.binary_name;
    let service_file_path = format!("/etc/systemd/system/{binary_name}.service");
    let server_ssh = args.server_ssh.as_ref();
    let sh = Shell::new()?;

    // Remove service file
    cmd!(sh, "ssh {server_ssh} rm -f {service_file_path}").run()?;

    // Transfer service file
    let temp_file_path = temp_file.path();
    cmd!(sh, "scp {temp_file_path} {server_ssh}:{service_file_path}").run()?;

    // Enable service
    cmd!(sh, "ssh {server_ssh} systemctl enable {service_file_path}").run()?;

    Ok(())
}

fn service_text(
    server_path: &str,
    binary_name: &str,
    binary_args: &[Arc<str>],
    user: &str,
    group: &str,
) -> String {
    let mut args = String::new();
    for arg in binary_args {
        args.push('\"');
        args.push_str(arg);
        args.push('\"');
        args.push(' ');
    }
    format!(
        "[Unit]
Description={binary_name}
After=network.target

[Service]
ExecStart=/bin/sh -c \'{server_path}/{binary_name} {args}\'
User={user}
Group={group}

[Install]
WantedBy=multi-user.target
"
    )
}

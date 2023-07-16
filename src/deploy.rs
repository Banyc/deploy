use std::{
    io::{self, BufRead},
    path::Path,
    sync::Arc,
};

use clap::Args;
use time::OffsetDateTime;
use xshell::{cmd, Shell};

#[derive(Debug, Args)]
pub struct DeployArgs {
    /// e.g.: `user@server-address`
    pub server_ssh: Arc<str>,
    /// e.g.: `"/path/to/remote/directory/"`
    pub server_path: Arc<str>,
    /// e.g.: `example`
    pub binary_name: Arc<str>,
}

impl DeployArgs {
    pub fn server_restart_command(&self) -> String {
        format!("systemctl restart {}", self.binary_name)
    }

    pub fn output_file_path(&self) -> String {
        format!(
            "./target/x86_64-unknown-linux-musl/release/{}",
            self.binary_name
        )
    }
}

pub fn deploy(args: DeployArgs) -> Result<(), Box<dyn std::error::Error>> {
    let args = std::dbg!(args);

    let file_hash = file_hash(args.output_file_path())?;

    let sh = Shell::new()?;
    let commit_hash = cmd!(sh, "git rev-parse HEAD").read()?;
    let remote_file_name = remote_file_name(&args.binary_name, &commit_hash, &file_hash);
    let remote_file_name = std::dbg!(remote_file_name);

    transfer_file(
        &sh,
        &args.server_ssh,
        &args.server_path,
        &args.output_file_path(),
        &remote_file_name,
    )?;

    start_server(
        &sh,
        &args.server_ssh,
        &args.server_path,
        &remote_file_name,
        &args.binary_name,
        &args.server_restart_command(),
    )?;

    Ok(())
}

fn remote_file_name(binary_name: &str, commit_hash: &str, file_hash: &str) -> String {
    let build_timestamp = OffsetDateTime::now_utc().unix_timestamp();
    format!(
        "{}-{}-{}-{}",
        binary_name, commit_hash, build_timestamp, file_hash
    )
}

fn file_hash<P>(file_path: P) -> io::Result<String>
where
    P: AsRef<Path>,
{
    let mut binary = std::fs::File::open(file_path)?;
    let mut reader = std::io::BufReader::new(&mut binary);
    let mut hasher = blake3::Hasher::new();
    while !reader.fill_buf()?.is_empty() {
        hasher.update(reader.buffer());
        reader.consume(reader.buffer().len());
    }
    let hash = hasher.finalize();
    Ok(hash.to_string())
}

fn transfer_file(
    sh: &Shell,
    server_ssh: &str,
    server_path: &str,
    file_path: &str,
    remote_file_name: &str,
) -> Result<(), xshell::Error> {
    // make sure the remote directory exists
    let make_dir = format!("mkdir -p {server_path}/versions/");
    cmd!(sh, "ssh {server_ssh} {make_dir}").run()?;

    // transfer the file
    cmd!(
        sh,
        "scp {file_path} {server_ssh}:{server_path}/versions/{remote_file_name}"
    )
    .run()?;

    Ok(())
}

fn start_server(
    sh: &Shell,
    server_ssh: &str,
    server_path: &str,
    remote_file_name: &str,
    binary_name: &str,
    server_restart_command: &str,
) -> Result<(), xshell::Error> {
    let ssh_cmd = format!(
        "nohup sh -c \"\\
        rm -f {server_path}/{binary_name} && \\
        ln -s {server_path}/versions/{remote_file_name} {server_path}/{binary_name} && \\
        chmod +x {server_path}/{binary_name} && \\
        {server_restart_command} \""
    );

    cmd!(sh, "ssh -q -T {server_ssh} {ssh_cmd}").run()?;

    Ok(())
}

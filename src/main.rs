use clap::{Parser, Subcommand};
use deploy::deploy::{deploy, DeployArgs};

#[derive(Debug, Parser)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Deploy(DeployArgs),
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Command::Deploy(deploy_args) => deploy(deploy_args)?,
    }

    Ok(())
}

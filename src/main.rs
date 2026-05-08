mod cli;
mod manage;
mod state;

use std::error::Error;

use clap::Parser;
use cli::{Cli, Commands, IpsetCommands};

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error + Send + Sync>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Daemon => manage::run_daemon(),
        Commands::Ipset { command } => match command {
            IpsetCommands::Create {
                name,
                allowed_domains,
            } => manage::send_create(&name, &allowed_domains),
            IpsetCommands::Remove { name } => manage::send_remove(&name),
        },
    }
}

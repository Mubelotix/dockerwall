mod cli;
mod ipset;
mod manage;
mod proxy;
mod state;

use clap::Parser;
use cli::{Cli, Commands, IpsetCommands};

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Daemon {
            dns_listen_addr,
            dns_upstream_addr,
        } => manage::run_daemon(&dns_listen_addr, &dns_upstream_addr),
        Commands::Ipset { command } => match command {
            IpsetCommands::Create {
                name,
                allowed_domains,
            } => manage::send_create(&name, &allowed_domains),
            IpsetCommands::Remove { name } => manage::send_remove(&name),
        },
    };

    if let Err(err) = result {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

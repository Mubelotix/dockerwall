use std::error::Error;

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "dockerwall", version, about = "Dockerwall daemon and ipset manager")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run the daemon and open the local DNS proxy listener.
    Daemon,
    /// Manage daemon-controlled ipsets.
    Ipset {
        #[command(subcommand)]
        command: IpsetCommands,
    },
}

#[derive(Subcommand, Debug)]
enum IpsetCommands {
    /// Create an ipset with one or more allowed domains.
    Create {
        name: String,
        #[arg(required = true, num_args = 1..)]
        allowed_domains: Vec<String>,
    },
    /// Remove an existing ipset.
    Remove { name: String },
}

pub fn run() -> Result<(), Box<dyn Error + Send + Sync>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Daemon => todo!(),
        Commands::Ipset { command } => match command {
            IpsetCommands::Create {
                name: _,
                allowed_domains: _,
            } => todo!(),
            IpsetCommands::Remove { name: _ } => todo!(),
        },
    }
}

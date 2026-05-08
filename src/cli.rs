use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "dockerwall", version, about = "Dockerwall daemon and ipset manager")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Run the daemon and open the local DNS proxy listener.
    Daemon,
    /// Manage daemon-controlled ipsets.
    Ipset {
        #[command(subcommand)]
        command: IpsetCommands,
    },
}

#[derive(Subcommand, Debug)]
pub enum IpsetCommands {
    /// Create an ipset with one or more allowed domains.
    Create {
        name: String,
        #[arg(required = true, num_args = 1..)]
        allowed_domains: Vec<String>,
    },
    /// Remove an existing ipset.
    Remove { name: String },
}

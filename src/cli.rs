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
    Daemon {
        #[arg(long, default_value = "127.0.0.1:5353")]
        dns_listen_addr: String,
        #[arg(long, default_value = "1.1.1.1:53")]
        dns_upstream_addr: String,
    },
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

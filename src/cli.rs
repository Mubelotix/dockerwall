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
        #[arg(long)]
        dns_upstream_addr: Option<String>,
    },
    /// Prepare a Docker network, ipset, and firewall rules for allowed domains.
    PrepareNetwork {
        name: String,
        #[arg(num_args = 0..)]
        domain_patterns: Vec<String>,
    },
    /// Manage daemon-controlled ipsets.
    Ipset {
        #[command(subcommand)]
        command: IpsetCommands,
    },
    /// Stream unmanaged domains resolved by the proxy.
    Record,
}

#[derive(Subcommand, Debug)]
pub enum IpsetCommands {
    /// Create an ipset with one or more allowed domains.
    Create {
        name: String,
        #[arg(num_args = 0..)]
        allowed_domains: Vec<String>,
    },
    /// Remove an existing ipset.
    Remove { name: String },
}

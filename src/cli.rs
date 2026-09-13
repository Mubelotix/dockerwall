use clap::{Parser, Subcommand, ValueEnum};

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum ContainerRuntime {
    Docker,
    Podman,
}

#[derive(Parser, Debug)]
#[command(name = "dockerwall", version, about = "Dockerwall daemon and ipset manager")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Show DNS resolution statistics.
    Stats,
    /// Run the daemon and open the local DNS proxy listener.
    Daemon {
        #[arg(long, default_value = "127.0.0.1:5353")]
        dns_listen_addr: String,
        #[arg(long)]
        dns_upstream_addr: Option<String>,
        #[arg(long, default_value = "86400")]
        stats_ttl: u64,
    },
    /// Prepare a container network, ipset, and firewall rules for allowed domains.
    PrepareNetwork {
        #[arg(long, value_enum, default_value = "docker")]
        runtime: ContainerRuntime,
        /// Outbound host interface for rootless Podman pasta traffic.
        #[arg(long)]
        interface: Option<String>,
        name: String,
        #[arg(num_args = 0..)]
        domain_patterns: Vec<String>,
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
        #[arg(num_args = 0..)]
        allowed_domains: Vec<String>,
    },
    /// Remove an existing ipset.
    Remove { name: String },
}

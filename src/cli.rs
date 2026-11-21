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
    /// Prepare a container network with firewall rules for allowed destinations.
    PrepareNetwork {
        #[arg(long, value_enum, default_value = "docker")]
        runtime: ContainerRuntime,
        /// Outbound host interface for rootless Podman pasta traffic.
        #[arg(long)]
        interface: Option<String>,
        name: String,
        /// Domain pattern, IP address, or IP:port (use [IPv6]:port for IPv6).
        #[arg(num_args = 0..)]
        allowed_destinations: Vec<String>,
    },
    /// Manage daemon-controlled ipsets.
    Ipset {
        #[command(subcommand)]
        command: IpsetCommands,
    },
}

#[derive(Subcommand, Debug)]
pub enum IpsetCommands {
    /// Create or replace a daemon-managed destination policy.
    Create {
        name: String,
        /// Domain pattern, IP address, or IP:port (use [IPv6]:port for IPv6).
        #[arg(num_args = 0..)]
        allowed_destinations: Vec<String>,
    },
    /// Remove an existing ipset.
    Remove { name: String },
}

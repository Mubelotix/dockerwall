mod cli;
mod control;
mod daemon;
mod helper;
mod ipset;
mod manage;
mod proxy;
mod state;
mod stats;
mod trust;

use std::net::IpAddr;

use clap::Parser;
use cli::{Cli, Commands, IpsetCommands};

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Stats => stats::send_stats().await,
        Commands::Daemon {
            dns_listen_addr,
            dns_upstream_addr,
            stats_ttl,
        } => {
            let dns_upstream_addr = match dns_upstream_addr {
                Some(addr) => addr,
                None => resolve_upstream_from_resolv_conf().await.unwrap_or_else(|| "1.1.1.1:53".to_owned()),
            };

            let stats_ttl = std::time::Duration::from_secs(stats_ttl);

            daemon::run_daemon(&dns_listen_addr, &dns_upstream_addr, stats_ttl).await
        }
        Commands::PrepareNetwork {
            name,
            domain_patterns,
        } => helper::prepare_network(&name, &domain_patterns).await,
        Commands::Ipset { command } => match command {
            IpsetCommands::Create {
                name,
                allowed_domains,
            } => manage::send_create(&name, None, &allowed_domains).await,
            IpsetCommands::Remove { name } => manage::send_remove(&name).await,
        },
    };

    if let Err(err) = result {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

async fn resolve_upstream_from_resolv_conf() -> Option<String> {
    let contents = tokio::fs::read_to_string("/etc/resolv.conf").await.ok()?;

    for raw_line in contents.lines() {
        let line = raw_line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }

        let mut parts = line.split_whitespace();
        let Some(first) = parts.next() else { continue };
        if first != "nameserver" {
            continue;
        }

        let Some(ip_text) = parts.next() else { continue };
        let Ok(ip) = ip_text.parse::<IpAddr>() else { continue };

        return Some(match ip {
            IpAddr::V4(addr) => format!("{addr}:53"),
            IpAddr::V6(addr) => format!("[{addr}]:53"),
        });
    }

    None
}

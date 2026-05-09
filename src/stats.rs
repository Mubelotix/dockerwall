use std::error::Error;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::LazyLock;
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use crate::control::CONTROL_SOCKET_PATH;

#[derive(Debug, Clone)]
pub struct StatEntry {
    pub count: u64,
    pub last_seen: SystemTime,
    pub network_id: Option<u32>,
    pub accepted: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct NetworkInfo {
    pub name: String,
    pub subnet: String,
}

/// Statistics mapping (domain, origin_ip) to their resolve count and last resolve timestamp.
pub static STATS: LazyLock<RwLock<HashMap<(String, IpAddr), StatEntry>>> = LazyLock::new(|| {
    RwLock::new(HashMap::new())
});

/// Mapping of network ID to network information.
pub static NETWORK_REGISTRY: LazyLock<RwLock<HashMap<u32, NetworkInfo>>> = LazyLock::new(|| {
    RwLock::new(HashMap::new())
});

/// Mapping of subnet (CIDR) to network ID.
pub static SUBNET_TO_ID: LazyLock<RwLock<HashMap<String, u32>>> = LazyLock::new(|| {
    RwLock::new(HashMap::new())
});

static NEXT_NETWORK_ID: AtomicU32 = AtomicU32::new(1);

pub async fn register_network(name: String, subnet: String) {
    let mut subnet_map = SUBNET_TO_ID.write().await;
    let mut registry = NETWORK_REGISTRY.write().await;

    if let Some(&id) = subnet_map.get(&subnet) {
        // Update existing network info if name changed? Or just keep it.
        registry.insert(id, NetworkInfo { name, subnet });
        return;
    }

    let id = NEXT_NETWORK_ID.fetch_add(1, Ordering::SeqCst);
    subnet_map.insert(subnet.clone(), id);
    registry.insert(id, NetworkInfo { name, subnet });
}

pub async fn record_resolve(domain: &str, origin: IpAddr, ttl: Duration) {
    let now = SystemTime::now();
    
    let (network_id, network_name) = {
        let subnet_map = SUBNET_TO_ID.read().await;
        let id_opt = subnet_map.iter()
            .find(|(subnet, _)| ip_in_subnet(origin, subnet))
            .map(|(_, &id)| id);
        
        if let Some(id) = id_opt {
            let registry = NETWORK_REGISTRY.read().await;
            let name = registry.get(&id).map(|info| info.name.clone());
            (Some(id), name)
        } else {
            (None, None)
        }
    };

    let accepted = if let Some(name) = &network_name {
        Some(crate::state::is_domain_accepted_by_network(domain, name).await)
    } else {
        None
    };

    let mut stats = STATS.write().await;

    stats.retain(|_, entry| {
        now.duration_since(entry.last_seen).unwrap_or(Duration::ZERO) < ttl
    });

    let entry = stats.entry((domain.to_string(), origin)).or_insert(StatEntry {
        count: 0,
        last_seen: now,
        network_id,
        accepted,
    });
    entry.count += 1;
    entry.last_seen = now;
    entry.network_id = network_id;
    entry.accepted = accepted;
}

pub async fn get_stats_report() -> String {
    let registry = NETWORK_REGISTRY.read().await;
    let stats = STATS.read().await;
    let now = SystemTime::now();

    let mut report = String::new();

    // Group stats by (network_id, origin_ip)
    let mut grouped_stats: HashMap<(Option<u32>, IpAddr), Vec<(String, &StatEntry)>> = HashMap::new();
    for ((domain, origin), entry) in stats.iter() {
        grouped_stats.entry((entry.network_id, *origin)).or_default().push((domain.clone(), entry));
    }

    // Known networks
    let mut network_ids: Vec<u32> = registry.keys().cloned().collect();
    network_ids.sort();

    for id in network_ids {
        let info = registry.get(&id).unwrap();
        report.push_str(&format!("Network: {} ({})\n", info.name, info.subnet));

        let mut ips_in_network: Vec<IpAddr> = grouped_stats.keys()
            .filter(|(net_id, _)| *net_id == Some(id))
            .map(|(_, ip)| *ip)
            .collect();
        ips_in_network.sort();

        if ips_in_network.is_empty() {
            report.push_str("  No activity\n\n");
            continue;
        }

        let single_ip = ips_in_network.len() == 1;

        for ip in ips_in_network {
            let entries = grouped_stats.get(&(Some(id), ip)).unwrap();
            if !single_ip {
                report.push_str(&format!("  IP: {}\n", ip));
            }

            for (domain, entry) in entries {
                let last_ago = format_duration(now.duration_since(entry.last_seen).unwrap_or(Duration::ZERO));
                
                let (allowed_count, denied_count) = if entry.accepted == Some(true) {
                    (Some(entry.count), None)
                } else if entry.accepted == Some(false) {
                    (None, Some(entry.count))
                } else {
                    (None, None)
                };

                let mut status = String::new();
                if let Some(c) = allowed_count {
                    if c > 0 { status.push_str(&format!("{}✅ ", c)); }
                }
                if let Some(c) = denied_count {
                    if c > 0 { status.push_str(&format!("{}❌ ", c)); }
                }

                if single_ip {
                    report.push_str(&format!("  {:<15} {:<30} {:<10} {}\n", ip, domain, status, last_ago));
                } else {
                    report.push_str(&format!("    {:<30} {:<10} {}\n", domain, status, last_ago));
                }
            }
        }
        report.push('\n');
    }

    // Unknown networks
    let mut unknown_ips: Vec<IpAddr> = grouped_stats.keys()
        .filter(|(net_id, _)| net_id.is_none())
        .map(|(_, ip)| *ip)
        .collect();
    unknown_ips.sort();

    if !unknown_ips.is_empty() {
        report.push_str("Unknown Networks:\n");
        for ip in unknown_ips {
            report.push_str(&format!("  IP: {}\n", ip));
            let entries = grouped_stats.get(&(None, ip)).unwrap();
            for (domain, entry) in entries {
                let last_ago = format_duration(now.duration_since(entry.last_seen).unwrap_or(Duration::ZERO));
                report.push_str(&format!("    {:<30} {:<10} {}\n", domain, format!("{} resolves", entry.count), last_ago));
            }
        }
    }

    report
}

pub async fn send_stats() -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut stream = UnixStream::connect(CONTROL_SOCKET_PATH).await?;
    stream.write_all(b"STATS\n").await?;

    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    while reader.read_line(&mut line).await? > 0 {
        print!("{line}");
        line.clear();
    }
    Ok(())
}

fn format_duration(d: Duration) -> String {
    let secs = d.as_secs();
    if secs < 60 {
        format!("{}s ago", secs)
    } else if secs < 3600 {
        format!("{}m ago", secs / 60)
    } else if secs < 86400 {
        format!("{}h ago", secs / 3600)
    } else {
        format!("{}d ago", secs / 86400)
    }
}

fn ip_in_subnet(ip: IpAddr, subnet: &str) -> bool {
    let ip = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
        ip => ip,
    };

    let mut parts = subnet.split('/');
    let network_ip_str = parts.next().unwrap_or("");
    let prefix_len_str = parts.next().unwrap_or("");

    let Ok(network_ip) = network_ip_str.parse::<IpAddr>() else { return false };
    let Ok(prefix_len) = prefix_len_str.parse::<u32>() else { return false };

    match (ip, network_ip) {
        (IpAddr::V4(ip_v4), IpAddr::V4(net_v4)) => {
            let ip_u32 = u32::from(ip_v4);
            let net_u32 = u32::from(net_v4);
            let mask = if prefix_len == 0 {
                0
            } else if prefix_len >= 32 {
                0xFFFFFFFF
            } else {
                0xFFFFFFFF_u32 << (32 - prefix_len)
            };
            (ip_u32 & mask) == (net_u32 & mask)
        }
        (IpAddr::V6(ip_v6), IpAddr::V6(net_v6)) => {
            let ip_u128 = u128::from(ip_v6);
            let net_u128 = u128::from(net_v6);
            let mask = if prefix_len == 0 {
                0
            } else if prefix_len >= 128 {
                0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
            } else {
                0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF_u128 << (128 - prefix_len)
            };
            (ip_u128 & mask) == (net_u128 & mask)
        }
        _ => false,
    }
}

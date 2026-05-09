use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::LazyLock;
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;

#[derive(Debug, Clone)]
pub struct StatEntry {
    pub count: u64,
    pub last_seen: SystemTime,
    pub network_id: u32,
    pub accepted: bool,
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

pub fn register_network(name: String, subnet: String) {
    let mut subnet_map = SUBNET_TO_ID.blocking_write();
    let mut registry = NETWORK_REGISTRY.blocking_write();

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
        let id = match subnet_map.iter().find(|(subnet, _)| ip_in_subnet(origin, subnet)) {
            Some((_, &id)) => id,
            None => return, // Ignore resolutions from unknown networks
        };
        
        let registry = NETWORK_REGISTRY.read().await;
        let name = match registry.get(&id) {
            Some(info) => info.name.clone(),
            None => return, // Should not happen
        };
        (id, name)
    };

    let accepted = crate::state::is_domain_accepted_by_network(domain, &network_name).await;

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

fn ip_in_subnet(ip: IpAddr, subnet: &str) -> bool {
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

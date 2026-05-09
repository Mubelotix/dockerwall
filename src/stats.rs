use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::LazyLock;
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;

#[derive(Debug, Clone, Copy)]
pub struct StatEntry {
    pub count: u64,
    pub last_seen: SystemTime,
}

/// Statistics mapping (domain, origin_ip) to their resolve count and last resolve timestamp.
pub static STATS: LazyLock<RwLock<HashMap<(String, IpAddr), StatEntry>>> = LazyLock::new(|| {
    RwLock::new(HashMap::new())
});

pub async fn record_resolve(domain: &str, origin: IpAddr, ttl: Duration) {
    let now = SystemTime::now();
    let mut stats = STATS.write().await;

    stats.retain(|_, entry| {
        now.duration_since(entry.last_seen).unwrap_or(Duration::ZERO) < ttl
    });

    let entry = stats.entry((domain.to_string(), origin)).or_insert(StatEntry {
        count: 0,
        last_seen: now,
    });
    entry.count += 1;
    entry.last_seen = now;
}

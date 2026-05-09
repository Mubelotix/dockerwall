use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::LazyLock;
use std::time::SystemTime;
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

pub async fn record_resolve(domain: &str, origin: IpAddr) {
    let mut stats = STATS.write().await;
    let entry = stats.entry((domain.to_string(), origin)).or_insert(StatEntry {
        count: 0,
        last_seen: SystemTime::now(),
    });
    entry.count += 1;
    entry.last_seen = SystemTime::now();
}

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::LazyLock;

use tokio::sync::RwLock;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedIpset {
    pub allowed_domain_patterns: Vec<String>,
    pub ips: Vec<IpAddr>,
}

pub static STATE: LazyLock<RwLock<HashMap<String, ManagedIpset>>> = LazyLock::new(|| RwLock::new(HashMap::new()));

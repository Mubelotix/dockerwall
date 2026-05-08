use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::LazyLock;

use tokio::sync::broadcast;
use tokio::sync::RwLock;

pub static UNMATCHED_DOMAINS: LazyLock<broadcast::Sender<String>> = LazyLock::new(|| {
    let (tx, _) = broadcast::channel(1024);
    tx
});

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedIpset {
    pub allowed_domain_patterns: Vec<String>,
    pub ips: HashSet<IpAddr>,
}

pub static STATE: LazyLock<RwLock<HashMap<String, ManagedIpset>>> = LazyLock::new(|| RwLock::new(HashMap::new()));

pub async fn apply_resolved_ips(domains: &[String], resolved_ips: &[IpAddr]) -> Vec<(String, Vec<IpAddr>)> {
    if domains.is_empty() || resolved_ips.is_empty() {
        return Vec::new();
    }

    let mut changed_sets = Vec::new();
    let mut state = STATE.write().await;

    let mut matched_domains = HashSet::new();

    for (name, managed_ipset) in state.iter_mut() {
        let mut matches_current_ipset = false;
        
        for domain in domains {
            if managed_ipset.allowed_domain_patterns.iter().any(|pattern| domain_matches_pattern(domain, pattern)) {
                matched_domains.insert(domain.clone());
                matches_current_ipset = true;
            }
        }

        if !matches_current_ipset {
            continue;
        }

        let before_len = managed_ipset.ips.len();
        managed_ipset.ips.extend(resolved_ips.iter().copied());

        if managed_ipset.ips.len() != before_len {
            changed_sets.push((name.clone(), managed_ipset.ips.iter().copied().collect()));
        }
    }

    for domain in domains {
        if !matched_domains.contains(domain) {
            let _ = UNMATCHED_DOMAINS.send(domain.clone());
        }
    }

    changed_sets
}

fn domain_matches_pattern(domain: &str, pattern: &str) -> bool {
    let domain = normalize_domain(domain);
    let pattern = normalize_domain(pattern);

    if let Some(suffix) = pattern.strip_prefix("*.") {
        return domain == suffix || domain.ends_with(&format!(".{suffix}"));
    }

    domain == pattern
}

fn normalize_domain(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

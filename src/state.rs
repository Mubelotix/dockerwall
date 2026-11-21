use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::LazyLock;
use tokio::sync::RwLock;

use crate::ipset::add_resolved_ips;

#[derive(Debug, Default, PartialEq, Eq)]
pub struct ManagedIpset {
    pub allowed_domain_patterns: Vec<String>,
    pub ips: HashSet<IpAddr>,
    pub endpoints: HashSet<(IpAddr, u16)>,
}

impl ManagedIpset {
    pub fn parse(destinations: &str) -> Result<Self, String> {
        let mut policy = Self::default();
        for entry in destinations
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            if let Ok(ip) = entry.parse::<IpAddr>() {
                policy.ips.insert(ip);
            } else if let Ok(endpoint) = entry.parse::<SocketAddr>() {
                // Scoped addresses are interface-specific and ipsets cannot represent the scope.
                if entry.contains('%') || endpoint.port() == 0 {
                    return Err(format!("invalid IP endpoint: {entry}"));
                }
                policy.endpoints.insert((endpoint.ip(), endpoint.port()));
            } else if entry.contains([':', '[', ']', '/', '%']) {
                return Err(format!(
                    "invalid destination: {entry} (use [IPv6]:port for IPv6 with a port)"
                ));
            } else {
                policy.allowed_domain_patterns.push(entry.to_owned());
            }
        }
        Ok(policy)
    }

    fn allows_domain(&self, domain: &str) -> bool {
        self.allowed_domain_patterns
            .iter()
            .any(|pattern| domain_matches_pattern(domain, pattern))
    }
}

pub static STATE: LazyLock<RwLock<HashMap<String, ManagedIpset>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

pub async fn apply_resolved_ips(domains: &[String], resolved_ips: &[IpAddr]) {
    if domains.is_empty() || resolved_ips.is_empty() {
        return;
    }

    // Serialize kernel writes with policy creation and removal.
    let mut state = STATE.write().await;

    for (name, managed_ipset) in state.iter_mut() {
        if !domains
            .iter()
            .any(|domain| managed_ipset.allows_domain(domain))
        {
            continue;
        }

        let new_ips: HashSet<_> = resolved_ips
            .iter()
            .copied()
            .filter(|ip| !managed_ipset.ips.contains(ip))
            .collect();
        if !new_ips.is_empty() {
            match add_resolved_ips(name, &new_ips).await {
                Ok(()) => managed_ipset.ips.extend(new_ips),
                Err(err) => eprintln!("ipset update error for {name}: {err}"),
            }
        }
    }
}

pub async fn is_domain_accepted_by_network(domain: &str, network_name: &str) -> bool {
    let state = STATE.read().await;
    state
        .get(network_name)
        .is_some_and(|policy| policy.allows_domain(domain))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_mixed_allowlist_and_treats_unbracketed_ipv6_as_an_address() {
        let policy = ManagedIpset::parse(
            " *.example.com, example.net, 192.0.2.1, 192.0.2.1, 2001:db8::80, 192.0.2.2:443, [2001:db8::2]:65535, ",
        )
        .unwrap();
        assert!(policy.allows_domain("Sub.Example.Com."));
        assert!(policy.allows_domain("example.net"));
        assert!(!policy.allows_domain("192.0.2.1"));
        assert_eq!(
            policy.ips,
            ["192.0.2.1", "2001:db8::80"]
                .map(|s| s.parse().unwrap())
                .into()
        );
        assert_eq!(
            policy.endpoints,
            [
                ("192.0.2.2".parse().unwrap(), 443),
                ("2001:db8::2".parse().unwrap(), 65535),
            ]
            .into()
        );
    }

    #[test]
    fn rejects_malformed_endpoints() {
        for entry in [
            "192.0.2.1:65536",
            "192.0.2.1:0",
            "192.0.2.1:http",
            "192.0.2.1:",
            "[2001:db8::1]:-1",
            "[fe80::1%0]:443",
            "2001:db8::1::443",
            "example.com:443",
            "192.0.2.0/24",
        ] {
            assert!(ManagedIpset::parse(entry).is_err(), "{entry}");
        }
    }
}

use std::collections::HashSet;
use std::error::Error;
use std::fmt::Write;
use std::net::IpAddr;
use std::process::Stdio;

use tokio::process::Command;

use crate::state::ManagedIpset;
use crate::trust::is_trusted_binary;

const IPSET_CANDIDATES: [&str; 3] = ["/usr/sbin/ipset", "/sbin/ipset", "/usr/bin/ipset"];

pub fn ipv6_ipset_name(name: &str) -> String {
    format!("{name}-v6")
}

pub fn port_ipset_name(name: &str, ipv6: bool) -> String {
    let suffix = if ipv6 { "-p6" } else { "-p" };
    format!("{name}{suffix}")
}

pub fn ipset_specs(name: &str) -> [(String, &'static str, &'static str); 4] {
    [
        (name.to_owned(), "hash:ip", "inet"),
        (ipv6_ipset_name(name), "hash:ip", "inet6"),
        (port_ipset_name(name, false), "hash:ip,port", "inet"),
        (port_ipset_name(name, true), "hash:ip,port", "inet6"),
    ]
}

pub fn validate_ipset_name(name: &str) -> Result<(), &'static str> {
    if name.is_empty()
        || name.len() > 28
        || name.starts_with('-')
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
    {
        return Err(
            "ipset name must be 1–28 characters, use only letters, digits, '_', '.', or '-', and not start with '-'",
        );
    }
    Ok(())
}

pub async fn replace_policy(
    name: &str,
    policy: &ManagedIpset,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    restore(&policy_payload(name, policy)).await
}

fn policy_payload(name: &str, policy: &ManagedIpset) -> String {
    let mut payload = String::new();
    for (set, _, _) in ipset_specs(name) {
        writeln!(payload, "flush {set}").unwrap();
    }
    payload.push_str(&address_payload(name, &policy.ips));
    for &(ip, port) in &policy.endpoints {
        let set = port_ipset_name(name, ip.is_ipv6());
        for protocol in ["tcp", "udp"] {
            writeln!(payload, "add {set} {ip},{protocol}:{port} -exist").unwrap();
        }
    }
    payload
}

pub async fn add_resolved_ips(
    name: &str,
    ips: &HashSet<IpAddr>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    restore(&address_payload(name, ips)).await
}

fn address_payload(name: &str, ips: &HashSet<IpAddr>) -> String {
    let ipv6_name = ipv6_ipset_name(name);
    let mut payload = String::new();
    for ip in ips {
        let ipset = match ip {
            IpAddr::V4(_) => name,
            IpAddr::V6(_) => &ipv6_name,
        };
        writeln!(payload, "add {ipset} {ip} -exist").unwrap();
    }
    payload
}

async fn restore(payload: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
    let ipset_binary = resolve_ipset_binary().await?;
    let mut child = Command::new(ipset_binary)
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .arg("restore")
        .spawn()?;

    if let Some(mut stdin) = child.stdin.take() {
        use tokio::io::AsyncWriteExt;
        stdin.write_all(payload.as_bytes()).await?;
    }

    let output = child.wait_with_output().await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        return Err(format!("ipset restore failed: {stderr}; stdout: {stdout}").into());
    }

    Ok(())
}

async fn resolve_ipset_binary() -> Result<&'static str, Box<dyn Error + Send + Sync>> {
    for candidate in IPSET_CANDIDATES {
        if is_trusted_binary(candidate).await? {
            return Ok(candidate);
        }
    }
    Err("trusted ipset binary not found".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn installs_static_addresses_and_tcp_udp_endpoints_in_separate_sets() {
        let policy = ManagedIpset::parse(
            "example.com,192.0.2.1,2001:db8::1,192.0.2.2:443,[2001:db8::2]:5353",
        )
        .unwrap();
        let payload = policy_payload("test", &policy);
        assert!(payload.starts_with("flush test\nflush test-v6\nflush test-p\nflush test-p6\n"));
        let entries: HashSet<_> = payload.lines().skip(4).collect();
        assert_eq!(
            entries,
            [
                "add test 192.0.2.1 -exist",
                "add test-v6 2001:db8::1 -exist",
                "add test-p 192.0.2.2,tcp:443 -exist",
                "add test-p 192.0.2.2,udp:443 -exist",
                "add test-p6 2001:db8::2,tcp:5353 -exist",
                "add test-p6 2001:db8::2,udp:5353 -exist",
            ]
            .into()
        );
    }

    #[test]
    fn dns_updates_only_add_to_address_sets() {
        let payload = address_payload("test", &["192.0.2.10".parse().unwrap()].into());
        assert_eq!(payload, "add test 192.0.2.10 -exist\n");
    }
}

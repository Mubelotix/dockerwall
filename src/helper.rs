use std::collections::hash_map::DefaultHasher;
use std::error::Error;
use std::ffi::{OsStr, OsString};
use std::hash::{Hash, Hasher};
use std::net::Ipv4Addr;
use std::process::{Output, Stdio};
use std::time::Duration;

use tokio::process::Command;
use tokio::time::sleep;

use crate::cli::ContainerRuntime;
use crate::control::get_dns_port;
use crate::manage::send_create;
use crate::trust::is_trusted_binary;

const IPSET_CANDIDATES: [&str; 3] = ["/usr/sbin/ipset", "/sbin/ipset", "/usr/bin/ipset"];
const DOCKER_CANDIDATES: [&str; 3] = ["/usr/bin/docker", "/bin/docker", "/usr/local/bin/docker"];
const IPTABLES_CANDIDATES: [&str; 2] = ["/usr/sbin/iptables", "/sbin/iptables"];
const IP_CANDIDATES: [&str; 3] = ["/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip"];
const PODMAN_OUTPUT_CHAIN: &str = "DOCKERWALL-OUTPUT";
const ROOTLESS_DNS_IP: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 1);
const ROOTLESS_DNS_CIDR: &str = "198.18.0.1/32";
const ROOTLESS_DNS_REDIRECT_CIDR: &str = "127.0.0.1/32";

const NETWORK_BASE_OCTET: u8 = 30;
const NETWORK_PREFIX_OCTET: u8 = 172;
const NETWORK_PREFIX_LENGTH: u8 = 28;
const USABLE_HOSTS_PER_SUBNET: u16 = 14;
const SUBNET_SLOTS: u64 = 256 * USABLE_HOSTS_PER_SUBNET as u64;

pub async fn prepare_network(
    name: &str,
    domain_patterns: &[String],
    runtime: ContainerRuntime,
    interface: Option<&str>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    match runtime {
        ContainerRuntime::Docker => {
            if interface.is_some() {
                return Err("--interface is only valid with --runtime podman".into());
            }
            prepare_docker_network(name, domain_patterns).await
        }
        // Podman uses pasta in the calling user's rootless session. Dockerwall
        // configures only host resources and never enters that user namespace.
        ContainerRuntime::Podman => {
            prepare_rootless_podman_network(name, domain_patterns, interface).await
        }
    }
}

async fn prepare_docker_network(
    name: &str,
    domain_patterns: &[String],
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let dns_port = get_dns_port().await?;

    let mut last_err = None;
    for attempt in 0u32..50 {
        let plan = NetworkPlan::new(name, dns_port, attempt);
        match setup_docker_resources(&plan).await {
            Ok(()) => {
                send_create(name, Some(&plan.subnet), domain_patterns).await?;
                return Ok(());
            }
            Err(err) => {
                eprintln!("network setup attempt {attempt} failed: {err}, retrying...");
                last_err = Some(err);
                sleep(Duration::from_millis(100)).await;
            }
        }
    }

    Err(last_err.unwrap_or_else(|| "failed to allocate network after 50 attempts".into()))
}

async fn prepare_rootless_podman_network(
    name: &str,
    domain_patterns: &[String],
    requested_interface: Option<&str>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    ensure_host_root()?;

    let ip_binary = resolve_binary(&IP_CANDIDATES).await?;
    ensure_rootless_dns_alias(ip_binary).await?;
    let dns_port = ensure_rootless_dns_daemon().await?;

    let interface = match requested_interface {
        Some(interface) => validate_interface_name(interface)?.to_owned(),
        None => default_route_interface().await?,
    };
    let ipset_binary = resolve_binary(&IPSET_CANDIDATES).await?;
    let iptables_binary = resolve_binary(&IPTABLES_CANDIDATES).await?;
    let source_ip = allocate_rootless_podman_source_ip(iptables_binary, ip_binary, name).await?;
    let source_cidr = format!("{source_ip}/32");

    run_command_checked(
        ip_binary,
        [
            OsString::from("addr"),
            OsString::from("replace"),
            OsString::from(&source_cidr),
            OsString::from("dev"),
            OsString::from(&interface),
        ],
    )
    .await?;
    destroy_ipset(ipset_binary, name).await?;
    create_ipset(ipset_binary, name).await?;
    ensure_rootless_podman_rules(iptables_binary, name, &source_cidr, &interface, dns_port).await?;
    send_create(name, Some(&source_cidr), domain_patterns).await?;

    println!("rootless Podman source IP: {source_ip}");
    println!("rootless Podman interface: {interface}");
    println!(
        "podman run --network pasta:--outbound,{source_ip} --dns {ROOTLESS_DNS_IP} <image> <command>"
    );
    Ok(())
}

async fn ensure_rootless_dns_alias(ip_binary: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
    run_command_checked(
        ip_binary,
        [
            OsString::from("addr"),
            OsString::from("replace"),
            OsString::from(ROOTLESS_DNS_CIDR),
            OsString::from("dev"),
            OsString::from("lo"),
        ],
    )
    .await?;
    Ok(())
}

async fn ensure_rootless_dns_daemon() -> Result<u16, Box<dyn Error + Send + Sync>> {
    match get_dns_port().await {
        Ok(port) => return Ok(port),
        Err(_) => {}
    }

    let executable = std::env::current_exe()?;
    let child = Command::new(executable)
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(false)
        .args(["daemon"])
        .spawn()?;
    let pid = child
        .id()
        .ok_or("could not determine external daemon PID")?;
    println!("started external host Dockerwall daemon (pid {pid})");

    for _ in 0..50 {
        match get_dns_port().await {
            Ok(port) => return Ok(port),
            Err(_) => sleep(Duration::from_millis(100)).await,
        }
    }

    Err("external host Dockerwall daemon did not become ready".into())
}

fn ensure_host_root() -> Result<(), Box<dyn Error + Send + Sync>> {
    let status = std::fs::read_to_string("/proc/self/status")?;
    let uid_line = status
        .lines()
        .find(|line| line.starts_with("Uid:"))
        .ok_or("could not determine effective UID")?;
    let effective_uid = uid_line
        .split_whitespace()
        .nth(2)
        .ok_or("could not determine effective UID")?;
    if effective_uid != "0" {
        return Err("rootless Podman preparation must run as host root".into());
    }

    let uid_map = std::fs::read_to_string("/proc/self/uid_map")?;
    let host_uid = uid_map
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .ok_or("could not determine host UID mapping")?;
    if host_uid != "0" {
        return Err(
            "rootless Podman preparation must run as host root, not a user namespace root".into(),
        );
    }
    Ok(())
}

async fn default_route_interface() -> Result<String, Box<dyn Error + Send + Sync>> {
    let ip_binary = resolve_binary(&IP_CANDIDATES).await?;
    let output = run_command_checked(
        ip_binary,
        [
            OsString::from("route"),
            OsString::from("show"),
            OsString::from("default"),
        ],
    )
    .await?;
    let output = String::from_utf8_lossy(&output.stdout);

    for route in output.lines() {
        let mut fields = route.split_ascii_whitespace();
        if fields.next() != Some("default") {
            continue;
        }
        while let Some(field) = fields.next() {
            if field == "dev" {
                let interface = fields.next().ok_or("default route has no interface")?;
                return Ok(validate_interface_name(interface)?.to_owned());
            }
        }
    }

    Err("could not determine the default-route interface".into())
}

fn validate_interface_name(interface: &str) -> Result<&str, Box<dyn Error + Send + Sync>> {
    if interface.is_empty()
        || interface.len() > 15
        || !interface
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(
            "interface name must be 1-15 ASCII alphanumeric, '.', '_', or '-' characters".into(),
        );
    }
    Ok(interface)
}

async fn allocate_rootless_podman_source_ip(
    iptables_binary: &str,
    ip_binary: &str,
    name: &str,
) -> Result<Ipv4Addr, Box<dyn Error + Send + Sync>> {
    let output = run_command_checked(
        iptables_binary,
        [OsString::from("-S"), OsString::from("OUTPUT")],
    )
    .await?;
    let rules = String::from_utf8_lossy(&output.stdout);
    let own_marker = format!("dockerwall:{name}:output-hook");

    for line in rules.lines() {
        if line.contains(&own_marker) {
            if let Some(source_ip) = output_rule_source_ip(line) {
                return Ok(source_ip);
            }
        }
    }

    for attempt in 0..131_069 {
        let source_ip = rootless_podman_source_ip(name, attempt);
        let source_cidr = format!("{source_ip}/32");
        if rules.lines().any(|line| line.contains(&source_cidr)) {
            continue;
        }

        let output = run_command_checked(
            ip_binary,
            [
                OsString::from("-o"),
                OsString::from("-4"),
                OsString::from("addr"),
                OsString::from("show"),
                OsString::from("to"),
                OsString::from(&source_cidr),
            ],
        )
        .await?;
        if output.stdout.is_empty() {
            return Ok(source_ip);
        }
    }

    Err("all managed rootless Podman source addresses are in use".into())
}

fn output_rule_source_ip(rule: &str) -> Option<Ipv4Addr> {
    let mut fields = rule.split_ascii_whitespace();
    while let Some(field) = fields.next() {
        if field == "-s" {
            return fields.next()?.strip_suffix("/32")?.parse().ok();
        }
    }
    None
}

fn rootless_podman_source_ip(name: &str, attempt: u32) -> Ipv4Addr {
    // FNV-1a is stable across processes and releases, unlike a randomized map hasher.
    let hash = name
        .as_bytes()
        .iter()
        .fold(0xcbf29ce484222325_u64, |hash, byte| {
            (hash ^ u64::from(*byte)).wrapping_mul(0x100000001b3)
        });
    let offset = ((hash % 131_069) as u32 + attempt) % 131_069 + 2;
    let base = u32::from(Ipv4Addr::new(198, 18, 0, 0));
    Ipv4Addr::from(base + offset)
}

async fn setup_docker_resources(plan: &NetworkPlan) -> Result<(), Box<dyn Error + Send + Sync>> {
    let ipset_binary = resolve_binary(&IPSET_CANDIDATES).await?;
    let docker_binary = resolve_binary(&DOCKER_CANDIDATES).await?;
    let iptables_binary = resolve_binary(&IPTABLES_CANDIDATES).await?;

    destroy_ipset(ipset_binary, &plan.name).await?;
    create_ipset(ipset_binary, &plan.name).await?;
    remove_docker_network(docker_binary, &plan.name).await?;
    create_docker_network(docker_binary, plan).await?;
    ensure_docker_iptables_rules(iptables_binary, plan).await
}

struct NetworkPlan {
    name: String,
    subnet: String,
    gateway: String,
    dns_port: u16,
}

impl NetworkPlan {
    fn new(name: &str, dns_port: u16, attempt: u32) -> Self {
        let (subnet, gateway) = subnet_and_gateway(name, attempt);
        Self {
            name: name.to_owned(),
            subnet,
            gateway,
            dns_port,
        }
    }
}

fn subnet_and_gateway(name: &str, attempt: u32) -> (String, String) {
    let mut hasher = DefaultHasher::new();
    name.hash(&mut hasher);
    attempt.hash(&mut hasher);
    let slot = (hasher.finish() % SUBNET_SLOTS) as u16;
    let third = (slot / USABLE_HOSTS_PER_SUBNET) as u8;
    let fourth = (slot % USABLE_HOSTS_PER_SUBNET) as u8;

    let subnet =
        format!("{NETWORK_PREFIX_OCTET}.{NETWORK_BASE_OCTET}.{third}.0/{NETWORK_PREFIX_LENGTH}");
    let gateway = format!(
        "{NETWORK_PREFIX_OCTET}.{NETWORK_BASE_OCTET}.{third}.{}",
        fourth + 1
    );
    (subnet, gateway)
}

async fn resolve_binary(
    candidates: &'static [&'static str],
) -> Result<&'static str, Box<dyn Error + Send + Sync>> {
    for candidate in candidates {
        if is_trusted_binary(candidate).await? {
            return Ok(candidate);
        }
    }
    Err("trusted binary not found".into())
}

async fn destroy_ipset(binary: &str, name: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
    let _ =
        run_command_allow_failure(binary, [OsString::from("destroy"), OsString::from(name)]).await;
    Ok(())
}

async fn create_ipset(binary: &str, name: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
    let result = run_command_allow_failure(
        binary,
        [
            OsString::from("create"),
            OsString::from(name),
            OsString::from("hash:ip"),
            OsString::from("maxelem"),
            OsString::from("1000000000"),
            OsString::from("-exist"),
        ],
    )
    .await?;
    if result.status.success() {
        return Ok(());
    }

    let tmp_name = format!("{name}-tmp");
    let _ = run_command_allow_failure(
        binary,
        [OsString::from("destroy"), OsString::from(&tmp_name)],
    )
    .await;
    run_command_checked(
        binary,
        [
            OsString::from("create"),
            OsString::from(&tmp_name),
            OsString::from("hash:ip"),
            OsString::from("maxelem"),
            OsString::from("1000000000"),
        ],
    )
    .await?;

    let swap_result = run_command_allow_failure(
        binary,
        [
            OsString::from("swap"),
            OsString::from(name),
            OsString::from(&tmp_name),
        ],
    )
    .await?;
    if swap_result.status.success() {
        run_command_checked(
            binary,
            [OsString::from("destroy"), OsString::from(&tmp_name)],
        )
        .await?;
    } else {
        run_command_checked(
            binary,
            [
                OsString::from("rename"),
                OsString::from(&tmp_name),
                OsString::from(name),
            ],
        )
        .await?;
    }
    Ok(())
}

async fn remove_docker_network(
    binary: &str,
    name: &str,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let _ = run_command_allow_failure(
        binary,
        [
            OsString::from("network"),
            OsString::from("rm"),
            OsString::from(name),
        ],
    )
    .await;
    Ok(())
}

async fn create_docker_network(
    binary: &str,
    plan: &NetworkPlan,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    run_command_checked(
        binary,
        [
            OsString::from("network"),
            OsString::from("create"),
            OsString::from("--driver"),
            OsString::from("bridge"),
            OsString::from("--subnet"),
            OsString::from(&plan.subnet),
            OsString::from("--ip-range"),
            OsString::from(&plan.subnet),
            OsString::from("--gateway"),
            OsString::from(&plan.gateway),
            OsString::from(&plan.name),
        ],
    )
    .await?;
    Ok(())
}

async fn ensure_docker_iptables_rules(
    binary: &str,
    plan: &NetworkPlan,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    ensure_rule_present(
        binary,
        &[
            OsString::from("-I"),
            OsString::from("DOCKER-USER"),
            OsString::from("1"),
            OsString::from("-m"),
            OsString::from("comment"),
            OsString::from("--comment"),
            OsString::from("dockerwall:established"),
            OsString::from("-m"),
            OsString::from("conntrack"),
            OsString::from("--ctstate"),
            OsString::from("ESTABLISHED,RELATED"),
            OsString::from("-j"),
            OsString::from("ACCEPT"),
        ],
    )
    .await?;
    ensure_rule_present(
        binary,
        &[
            OsString::from("-I"),
            OsString::from("DOCKER-USER"),
            OsString::from("2"),
            OsString::from("-m"),
            OsString::from("comment"),
            OsString::from("--comment"),
            OsString::from(format!("dockerwall:{}:allow", plan.name)),
            OsString::from("-s"),
            OsString::from(&plan.subnet),
            OsString::from("-m"),
            OsString::from("set"),
            OsString::from("--match-set"),
            OsString::from(&plan.name),
            OsString::from("dst"),
            OsString::from("-j"),
            OsString::from("ACCEPT"),
        ],
    )
    .await?;
    ensure_rule_present(
        binary,
        &[
            OsString::from("-I"),
            OsString::from("DOCKER-USER"),
            OsString::from("3"),
            OsString::from("-m"),
            OsString::from("comment"),
            OsString::from("--comment"),
            OsString::from(format!("dockerwall:{}:allow-local", plan.name)),
            OsString::from("-s"),
            OsString::from(&plan.subnet),
            OsString::from("-d"),
            OsString::from("172.16.0.0/12"),
            OsString::from("-j"),
            OsString::from("ACCEPT"),
        ],
    )
    .await?;
    ensure_rule_present(
        binary,
        &[
            OsString::from("-I"),
            OsString::from("DOCKER-USER"),
            OsString::from("4"),
            OsString::from("-m"),
            OsString::from("comment"),
            OsString::from("--comment"),
            OsString::from(format!("dockerwall:{}:drop", plan.name)),
            OsString::from("-s"),
            OsString::from(&plan.subnet),
            OsString::from("-j"),
            OsString::from("DROP"),
        ],
    )
    .await?;
    ensure_rule_present(
        binary,
        &[
            OsString::from("-t"),
            OsString::from("nat"),
            OsString::from("-I"),
            OsString::from("PREROUTING"),
            OsString::from("-m"),
            OsString::from("comment"),
            OsString::from("--comment"),
            OsString::from(format!("dockerwall:{}:dns-udp", plan.name)),
            OsString::from("-s"),
            OsString::from(&plan.subnet),
            OsString::from("-p"),
            OsString::from("udp"),
            OsString::from("--dport"),
            OsString::from("53"),
            OsString::from("-j"),
            OsString::from("DNAT"),
            OsString::from("--to-destination"),
            OsString::from(format!("{}:{}", plan.gateway, plan.dns_port)),
        ],
    )
    .await?;
    ensure_rule_present(
        binary,
        &[
            OsString::from("-t"),
            OsString::from("nat"),
            OsString::from("-I"),
            OsString::from("PREROUTING"),
            OsString::from("-m"),
            OsString::from("comment"),
            OsString::from("--comment"),
            OsString::from(format!("dockerwall:{}:dns-tcp", plan.name)),
            OsString::from("-s"),
            OsString::from(&plan.subnet),
            OsString::from("-p"),
            OsString::from("tcp"),
            OsString::from("--dport"),
            OsString::from("53"),
            OsString::from("-j"),
            OsString::from("DNAT"),
            OsString::from("--to-destination"),
            OsString::from(format!("{}:{}", plan.gateway, plan.dns_port)),
        ],
    )
    .await?;
    Ok(())
}

async fn ensure_rootless_podman_rules(
    binary: &str,
    name: &str,
    source_cidr: &str,
    interface: &str,
    dns_port: u16,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    ensure_chain(binary, PODMAN_OUTPUT_CHAIN).await?;
    let dns_destination = if dns_port == 53 {
        ROOTLESS_DNS_CIDR
    } else {
        ROOTLESS_DNS_REDIRECT_CIDR
    };
    ensure_rule_present(
        binary,
        &[
            OsString::from("-I"),
            OsString::from("OUTPUT"),
            OsString::from("1"),
            OsString::from("-s"),
            OsString::from(source_cidr),
            OsString::from("-m"),
            OsString::from("comment"),
            OsString::from("--comment"),
            OsString::from(format!("dockerwall:{name}:output-hook")),
            OsString::from("-j"),
            OsString::from(PODMAN_OUTPUT_CHAIN),
        ],
    )
    .await?;
    ensure_rule_present(
        binary,
        &[
            OsString::from("-I"),
            OsString::from(PODMAN_OUTPUT_CHAIN),
            OsString::from("1"),
            OsString::from("-s"),
            OsString::from(source_cidr),
            OsString::from("-m"),
            OsString::from("comment"),
            OsString::from("--comment"),
            OsString::from(format!("dockerwall:{name}:established")),
            OsString::from("-m"),
            OsString::from("conntrack"),
            OsString::from("--ctstate"),
            OsString::from("ESTABLISHED,RELATED"),
            OsString::from("-j"),
            OsString::from("ACCEPT"),
        ],
    )
    .await?;
    ensure_rule_present(
        binary,
        &[
            OsString::from("-I"),
            OsString::from(PODMAN_OUTPUT_CHAIN),
            OsString::from("2"),
            OsString::from("-s"),
            OsString::from(source_cidr),
            OsString::from("-d"),
            OsString::from(dns_destination),
            OsString::from("-p"),
            OsString::from("udp"),
            OsString::from("--dport"),
            OsString::from(dns_port.to_string()),
            OsString::from("-m"),
            OsString::from("comment"),
            OsString::from("--comment"),
            OsString::from(format!("dockerwall:{name}:dns-udp")),
            OsString::from("-j"),
            OsString::from("ACCEPT"),
        ],
    )
    .await?;
    ensure_rule_present(
        binary,
        &[
            OsString::from("-I"),
            OsString::from(PODMAN_OUTPUT_CHAIN),
            OsString::from("3"),
            OsString::from("-s"),
            OsString::from(source_cidr),
            OsString::from("-d"),
            OsString::from(dns_destination),
            OsString::from("-p"),
            OsString::from("tcp"),
            OsString::from("--dport"),
            OsString::from(dns_port.to_string()),
            OsString::from("-m"),
            OsString::from("comment"),
            OsString::from("--comment"),
            OsString::from(format!("dockerwall:{name}:dns-tcp")),
            OsString::from("-j"),
            OsString::from("ACCEPT"),
        ],
    )
    .await?;
    ensure_rule_present(
        binary,
        &[
            OsString::from("-I"),
            OsString::from(PODMAN_OUTPUT_CHAIN),
            OsString::from("4"),
            OsString::from("-s"),
            OsString::from(source_cidr),
            OsString::from("-d"),
            OsString::from(source_cidr),
            OsString::from("-p"),
            OsString::from("udp"),
            OsString::from("--sport"),
            OsString::from(dns_port.to_string()),
            OsString::from("-m"),
            OsString::from("comment"),
            OsString::from("--comment"),
            OsString::from(format!("dockerwall:{name}:dns-response-udp")),
            OsString::from("-j"),
            OsString::from("ACCEPT"),
        ],
    )
    .await?;
    ensure_rule_present(
        binary,
        &[
            OsString::from("-I"),
            OsString::from(PODMAN_OUTPUT_CHAIN),
            OsString::from("5"),
            OsString::from("-s"),
            OsString::from(source_cidr),
            OsString::from("-d"),
            OsString::from(source_cidr),
            OsString::from("-p"),
            OsString::from("tcp"),
            OsString::from("--sport"),
            OsString::from(dns_port.to_string()),
            OsString::from("-m"),
            OsString::from("comment"),
            OsString::from("--comment"),
            OsString::from(format!("dockerwall:{name}:dns-response-tcp")),
            OsString::from("-j"),
            OsString::from("ACCEPT"),
        ],
    )
    .await?;
    ensure_rule_present(
        binary,
        &[
            OsString::from("-I"),
            OsString::from(PODMAN_OUTPUT_CHAIN),
            OsString::from("6"),
            OsString::from("-s"),
            OsString::from(source_cidr),
            OsString::from("-m"),
            OsString::from("comment"),
            OsString::from("--comment"),
            OsString::from(format!("dockerwall:{name}:allow")),
            OsString::from("-m"),
            OsString::from("set"),
            OsString::from("--match-set"),
            OsString::from(name),
            OsString::from("dst"),
            OsString::from("-j"),
            OsString::from("ACCEPT"),
        ],
    )
    .await?;
    ensure_rule_present(
        binary,
        &[
            OsString::from("-I"),
            OsString::from(PODMAN_OUTPUT_CHAIN),
            OsString::from("7"),
            OsString::from("-s"),
            OsString::from(source_cidr),
            OsString::from("-m"),
            OsString::from("comment"),
            OsString::from("--comment"),
            OsString::from(format!("dockerwall:{name}:drop")),
            OsString::from("-j"),
            OsString::from("DROP"),
        ],
    )
    .await?;
    if dns_port != 53 {
        ensure_rootless_dns_redirects(binary, name, source_cidr, dns_port).await?;
    }
    ensure_rule_present(
        binary,
        &[
            OsString::from("-t"),
            OsString::from("nat"),
            OsString::from("-I"),
            OsString::from("POSTROUTING"),
            OsString::from("1"),
            OsString::from("-s"),
            OsString::from(source_cidr),
            OsString::from("-o"),
            OsString::from(interface),
            OsString::from("-m"),
            OsString::from("comment"),
            OsString::from("--comment"),
            OsString::from(format!("dockerwall:{name}:masquerade")),
            OsString::from("-j"),
            OsString::from("MASQUERADE"),
        ],
    )
    .await
}

async fn ensure_rootless_dns_redirects(
    binary: &str,
    name: &str,
    source_cidr: &str,
    dns_port: u16,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    for (chain, protocol) in [
        ("OUTPUT", "udp"),
        ("OUTPUT", "tcp"),
        ("PREROUTING", "udp"),
        ("PREROUTING", "tcp"),
    ] {
        ensure_rule_present(
            binary,
            &[
                OsString::from("-t"),
                OsString::from("nat"),
                OsString::from("-I"),
                OsString::from(chain),
                OsString::from("1"),
                OsString::from("-s"),
                OsString::from(source_cidr),
                OsString::from("-d"),
                OsString::from(ROOTLESS_DNS_CIDR),
                OsString::from("-p"),
                OsString::from(protocol),
                OsString::from("--dport"),
                OsString::from("53"),
                OsString::from("-m"),
                OsString::from("comment"),
                OsString::from("--comment"),
                OsString::from(format!("dockerwall:{name}:dns-{chain}-{protocol}")),
                OsString::from("-j"),
                OsString::from("REDIRECT"),
                OsString::from("--to-ports"),
                OsString::from(dns_port.to_string()),
            ],
        )
        .await?;
    }
    for protocol in ["udp", "tcp"] {
        ensure_rule_present(
            binary,
            &[
                OsString::from("-t"),
                OsString::from("nat"),
                OsString::from("-I"),
                OsString::from("POSTROUTING"),
                OsString::from("1"),
                OsString::from("-s"),
                OsString::from(source_cidr),
                OsString::from("-d"),
                OsString::from(source_cidr),
                OsString::from("-p"),
                OsString::from(protocol),
                OsString::from("--sport"),
                OsString::from(dns_port.to_string()),
                OsString::from("-m"),
                OsString::from("comment"),
                OsString::from("--comment"),
                OsString::from(format!("dockerwall:{name}:dns-response-snat-{protocol}")),
                OsString::from("-j"),
                OsString::from("SNAT"),
                OsString::from("--to-source"),
                OsString::from("127.0.0.1"),
            ],
        )
        .await?;
    }
    Ok(())
}

async fn ensure_chain(binary: &str, name: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
    let create_result =
        run_command_allow_failure(binary, [OsString::from("-N"), OsString::from(name)]).await?;
    if create_result.status.success() {
        return Ok(());
    }
    let exists_result =
        run_command_allow_failure(binary, [OsString::from("-S"), OsString::from(name)]).await?;
    if exists_result.status.success() {
        return Ok(());
    }
    Err(format!(
        "failed to create iptables chain {name}: {}",
        command_failure_message(&create_result)
    )
    .into())
}

async fn ensure_rule_present(
    binary: &str,
    args: &[OsString],
) -> Result<(), Box<dyn Error + Send + Sync>> {
    remove_rule_all(binary, &delete_args(args)).await?;
    run_command_checked(binary, args.iter().cloned()).await?;
    Ok(())
}

async fn remove_rule_all(
    binary: &str,
    args: &[OsString],
) -> Result<(), Box<dyn Error + Send + Sync>> {
    loop {
        if !run_command_allow_failure(binary, args.iter().cloned())
            .await?
            .status
            .success()
        {
            return Ok(());
        }
    }
}

fn delete_args(insert_args: &[OsString]) -> Vec<OsString> {
    let mut args = insert_args.to_vec();
    let Some(operation_index) = args.iter().position(|arg| arg == "-I" || arg == "-A") else {
        return args;
    };
    args[operation_index] = OsString::from("-D");
    let position_index = operation_index + 2;
    if args
        .get(position_index)
        .and_then(|position| position.to_str())
        .and_then(|position| position.parse::<u32>().ok())
        .is_some()
    {
        args.remove(position_index);
    }
    args
}

async fn run_command_allow_failure<I, S>(
    binary: &str,
    args: I,
) -> Result<Output, Box<dyn Error + Send + Sync>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    Ok(Command::new(binary)
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .args(args)
        .output()
        .await?)
}

async fn run_command_checked<I, S>(
    binary: &str,
    args: I,
) -> Result<Output, Box<dyn Error + Send + Sync>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let output = run_command_allow_failure(binary, args).await?;
    if output.status.success() {
        return Ok(output);
    }
    Err(command_failure_message(&output).into())
}

fn command_failure_message(output: &Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if stderr.is_empty() && stdout.is_empty() {
        "command failed".to_owned()
    } else if stdout.is_empty() {
        format!("command failed: {stderr}")
    } else if stderr.is_empty() {
        format!("command failed: stdout: {stdout}")
    } else {
        format!("command failed: {stderr}; stdout: {stdout}")
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::net::Ipv4Addr;

    use super::{
        ROOTLESS_DNS_IP, delete_args, rootless_podman_source_ip, subnet_and_gateway,
        validate_interface_name,
    };

    #[test]
    fn generated_gateways_are_valid_for_their_subnets() {
        for attempt in 0..1000 {
            let (subnet, gateway) = subnet_and_gateway("test-net", attempt);
            let subnet_prefix = subnet.strip_suffix(".0/28").unwrap();
            let subnet_octets: Vec<u8> = subnet_prefix
                .split('.')
                .map(|octet| octet.parse().unwrap())
                .collect();
            let gateway_octets: Vec<u8> = gateway
                .split('.')
                .map(|octet| octet.parse().unwrap())
                .collect();
            assert_eq!(&gateway_octets[..3], &subnet_octets[..]);
            assert!((1..=14).contains(&gateway_octets[3]));
        }
    }

    #[test]
    fn rootless_podman_source_ip_is_stable_and_in_benchmark_range() {
        let ip = rootless_podman_source_ip("test-net", 0);
        assert_eq!(ip, rootless_podman_source_ip("test-net", 0));
        assert_ne!(ip, rootless_podman_source_ip("test-net", 1));
        assert_ne!(ip, Ipv4Addr::new(198, 18, 0, 0));
        assert_ne!(ip, ROOTLESS_DNS_IP);
        assert_ne!(ip, Ipv4Addr::new(198, 19, 255, 255));
        assert!(
            (u32::from(Ipv4Addr::new(198, 18, 0, 0))..=u32::from(Ipv4Addr::new(198, 19, 255, 255)))
                .contains(&u32::from(ip))
        );
    }

    #[test]
    fn interface_names_are_conservative() {
        assert_eq!(validate_interface_name("enp0s3.100").unwrap(), "enp0s3.100");
        assert!(validate_interface_name("bad/interface").is_err());
        assert!(validate_interface_name("non-ascii-\u{e9}").is_err());
    }

    #[test]
    fn delete_args_remove_insert_positions() {
        let args = vec![
            OsString::from("-t"),
            OsString::from("nat"),
            OsString::from("-I"),
            OsString::from("POSTROUTING"),
            OsString::from("1"),
            OsString::from("-p"),
            OsString::from("udp"),
        ];
        assert_eq!(
            delete_args(&args),
            vec![
                OsString::from("-t"),
                OsString::from("nat"),
                OsString::from("-D"),
                OsString::from("POSTROUTING"),
                OsString::from("-p"),
                OsString::from("udp"),
            ]
        );
    }
}

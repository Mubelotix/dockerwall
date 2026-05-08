use std::collections::hash_map::DefaultHasher;
use std::error::Error;
use std::ffi::{OsStr, OsString};
use std::hash::{Hash, Hasher};
use std::process::Stdio;

use tokio::process::Command;
use tokio::runtime::Builder;

use crate::manage;
use crate::trust::is_trusted_binary;

const IPSET_CANDIDATES: [&str; 3] = ["/usr/sbin/ipset", "/sbin/ipset", "/usr/bin/ipset"];
const DOCKER_CANDIDATES: [&str; 3] = ["/usr/bin/docker", "/bin/docker", "/usr/local/bin/docker"];
const IPTABLES_CANDIDATES: [&str; 2] = ["/usr/sbin/iptables", "/sbin/iptables"];

const NETWORK_BASE_OCTET: u8 = 30;
const NETWORK_PREFIX_OCTET: u8 = 172;
const NETWORK_PREFIX_LENGTH: u8 = 28;

pub fn prepare_network(name: &str, domain_patterns: &[String]) -> Result<(), Box<dyn Error + Send + Sync>> {
    let runtime = Builder::new_current_thread().enable_io().build()?;
    let plan = NetworkPlan::new(name);

    runtime.block_on(setup_local_resources(&plan))?;
    manage::send_create(name, domain_patterns)?;

    Ok(())
}

async fn setup_local_resources(plan: &NetworkPlan) -> Result<(), Box<dyn Error + Send + Sync>> {
    let ipset_binary = resolve_binary(&IPSET_CANDIDATES)?;
    let docker_binary = resolve_binary(&DOCKER_CANDIDATES)?;
    let iptables_binary = resolve_binary(&IPTABLES_CANDIDATES)?;

    destroy_ipset(ipset_binary, &plan.name).await?;
    create_ipset(ipset_binary, &plan.name).await?;

    remove_docker_network(docker_binary, &plan.name).await?;
    create_docker_network(docker_binary, plan).await?;

    ensure_iptables_rules(iptables_binary, plan).await?;
    Ok(())
}


struct NetworkPlan {
    name: String,
    subnet: String,
    gateway: String,
}

impl NetworkPlan {
    fn new(name: &str) -> Self {
        let (subnet, gateway) = subnet_and_gateway(name);
        Self {
            name: name.to_owned(),
            subnet,
            gateway,
        }
    }
}

fn subnet_and_gateway(name: &str) -> (String, String) {
    let mut hasher = DefaultHasher::new();
    name.hash(&mut hasher);
    let slot = (hasher.finish() % 4096) as u16;
    let third = (slot / 16) as u8;
    let fourth = ((slot % 16) * 16) as u8;

    let subnet = format!(
        "{}.{}.{}.0/{NETWORK_PREFIX_LENGTH}",
        NETWORK_PREFIX_OCTET, NETWORK_BASE_OCTET, third
    );
    let gateway = format!("{}.{}.{}.{}", NETWORK_PREFIX_OCTET, NETWORK_BASE_OCTET, third, fourth + 1);

    (subnet, gateway)
}

fn resolve_binary(candidates: &'static [&'static str]) -> Result<&'static str, Box<dyn Error + Send + Sync>> {
    for candidate in candidates {
        if is_trusted_binary(candidate)? {
            return Ok(candidate);
        }
    }

    Err("trusted binary not found".into())
}

async fn destroy_ipset(binary: &str, name: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
    let _ = run_command_allow_failure(binary, [OsString::from("destroy"), OsString::from(name)]).await;
    Ok(())
}

async fn create_ipset(binary: &str, name: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
    run_command_checked(
        binary,
        [
            OsString::from("create"),
            OsString::from(name),
            OsString::from("hash:ip"),
            OsString::from("-exist"),
        ],
    )
    .await?;
    Ok(())
}

async fn remove_docker_network(binary: &str, name: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
    let _ = run_command_allow_failure(binary, [OsString::from("network"), OsString::from("rm"), OsString::from(name)]).await;
    Ok(())
}

async fn create_docker_network(binary: &str, plan: &NetworkPlan) -> Result<(), Box<dyn Error + Send + Sync>> {
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

async fn ensure_iptables_rules(binary: &str, plan: &NetworkPlan) -> Result<(), Box<dyn Error + Send + Sync>> {
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
            OsString::from(format!("dockerwall:{}:drop", plan.name)),
            OsString::from("-s"),
            OsString::from(&plan.subnet),
            OsString::from("-j"),
            OsString::from("DROP"),
        ],
    )
    .await?;

    Ok(())
}

async fn ensure_rule_present(binary: &str, args: &[OsString]) -> Result<(), Box<dyn Error + Send + Sync>> {
    remove_rule_all(binary, &delete_args(args)).await?;
    run_command_checked(binary, args.iter().cloned()).await?;
    Ok(())
}

async fn remove_rule_all(binary: &str, args: &[OsString]) -> Result<(), Box<dyn Error + Send + Sync>> {
    loop {
        let output = run_command_allow_failure(binary, args.iter().cloned()).await?;
        if !output.status.success() {
            break;
        }
    }
    Ok(())
}

fn delete_args(insert_args: &[OsString]) -> Vec<OsString> {
    let mut args = insert_args.to_vec();
    if let Some(first) = args.get_mut(0) {
        *first = OsString::from("-D");
    }
    args
}

async fn run_command_allow_failure<I, S>(binary: &str, args: I) -> Result<std::process::Output, Box<dyn Error + Send + Sync>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let output = Command::new(binary)
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .args(args)
        .output()
        .await?;

    Ok(output)
}

async fn run_command_checked<I, S>(binary: &str, args: I) -> Result<std::process::Output, Box<dyn Error + Send + Sync>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let output = run_command_allow_failure(binary, args).await?;

    if output.status.success() {
        return Ok(output);
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let message = if stderr.is_empty() && stdout.is_empty() {
        "command failed".to_owned()
    } else if stdout.is_empty() {
        format!("command failed: {stderr}")
    } else if stderr.is_empty() {
        format!("command failed: stdout: {stdout}")
    } else {
        format!("command failed: {stderr}; stdout: {stdout}")
    };

    Err(message.into())
}

use std::error::Error;
use std::net::IpAddr;
use std::process::Stdio;

use tokio::process::Command;

use crate::trust::is_trusted_binary;

const IPSET_CANDIDATES: [&str; 3] = ["/usr/sbin/ipset", "/sbin/ipset", "/usr/bin/ipset"];

pub async fn update_ipset(name: String, ips: Vec<IpAddr>) -> Result<(), Box<dyn Error + Send + Sync>> {
    let ipset_binary = resolve_ipset_binary()?;

    let ipv4s: Vec<IpAddr> = ips.into_iter().filter(|ip| matches!(ip, IpAddr::V4(_))).collect();

    run_ipset_command(ipset_binary, ["flush", &name]).await?;

    for ip in ipv4s {
        let ip_text = ip.to_string();
        run_ipset_command(ipset_binary, ["add", &name, &ip_text, "-exist"]).await?;
    }

    Ok(())
}

fn resolve_ipset_binary() -> Result<&'static str, Box<dyn Error + Send + Sync>> {
    for candidate in IPSET_CANDIDATES {
        if is_trusted_binary(candidate)? {
            return Ok(candidate);
        }
    }

    Err("trusted ipset binary not found".into())
}

async fn run_ipset_command<I, S>(binary: &str, args: I) -> Result<(), Box<dyn Error + Send + Sync>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
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

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();

    let message = if stderr.is_empty() && stdout.is_empty() {
        "ipset command failed".to_owned()
    } else if stdout.is_empty() {
        format!("ipset command failed: {stderr}")
    } else if stderr.is_empty() {
        format!("ipset command failed: stdout: {stdout}")
    } else {
        format!("ipset command failed: {stderr}; stdout: {stdout}")
    };

    Err(message.into())
}

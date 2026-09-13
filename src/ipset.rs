use std::error::Error;
use std::net::IpAddr;
use std::process::Stdio;

use tokio::process::Command;

use crate::trust::is_trusted_binary;

const IPSET_CANDIDATES: [&str; 3] = ["/usr/sbin/ipset", "/sbin/ipset", "/usr/bin/ipset"];

pub fn ipv6_ipset_name(name: &str) -> String {
    format!("{name}-v6")
}

pub async fn update_ipset(
    name: String,
    ips: Vec<IpAddr>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let ipset_binary = resolve_ipset_binary().await?;
    let ipv6_name = ipv6_ipset_name(&name);

    let mut payload = format!("flush {name}\nflush {ipv6_name}\n");
    for ip in ips {
        let ipset = match ip {
            IpAddr::V4(_) => &name,
            IpAddr::V6(_) => &ipv6_name,
        };
        payload.push_str(&format!("add {ipset} {ip} -exist\n"));
    }

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



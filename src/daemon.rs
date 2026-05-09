use std::error::Error;
use std::net::SocketAddr;
use std::time::Duration;

use crate::control::run_control_server;
use crate::proxy::run_dns_proxy;
use tokio::spawn;

pub async fn run_daemon(
    dns_listen_addr: &str,
    dns_upstream_addr: &str,
    stats_ttl: Duration,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let listen_addr: SocketAddr = dns_listen_addr.parse()?;
    let dns_port = listen_addr.port();
    let control_handle = spawn(run_control_server(dns_port));
    run_dns_proxy(dns_listen_addr, dns_upstream_addr, stats_ttl).await?;

    match control_handle.await {
        Ok(result) => result,
        Err(_) => Err("control server task panicked".into()),
    }
}

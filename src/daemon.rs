use std::error::Error;
use std::thread;
use std::time::Duration;

use crate::control::run_control_server;
use crate::proxy;

pub fn run_daemon(
    dns_listen_addr: &str,
    dns_upstream_addr: &str,
    stats_ttl: Duration,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let listen_addr: std::net::SocketAddr = dns_listen_addr.parse()?;
    let dns_port = listen_addr.port();
    let control_thread = thread::spawn(move || run_control_server(dns_port));
    proxy::run_dns_proxy(dns_listen_addr, dns_upstream_addr, stats_ttl)?;

    match control_thread.join() {
        Ok(result) => result,
        Err(_) => Err("control server thread panicked".into()),
    }
}

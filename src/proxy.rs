use std::collections::HashMap;
use std::error::Error;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use hickory_proto::op::Message;
use hickory_proto::rr::RData;
use tokio::net::UdpSocket;
use tokio::spawn;
use tokio::sync::{RwLock, Semaphore};
use tokio::time::timeout;

use crate::ipset::update_ipset;
use crate::state::apply_resolved_ips;
use crate::stats::record_resolve;

static PER_IP_LIMITS: LazyLock<RwLock<HashMap<IpAddr, Arc<Semaphore>>>> = LazyLock::new(|| {
    RwLock::new(HashMap::new())
});

const MAX_CONCURRENT_PER_IP: usize = 32;
const MAX_CONCURRENT_GLOBAL: usize = 10000;

pub async fn run_dns_proxy(
    dns_listen_addr: &str,
    dns_upstream_addr: &str,
    stats_ttl: Duration,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let listener = Arc::new(UdpSocket::bind(dns_listen_addr).await?);
    let upstream_addr: SocketAddr = dns_upstream_addr.parse()?;
    let global_semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_GLOBAL));
    println!("dockerwall dns proxy listening on {dns_listen_addr}");

    loop {
        let mut request_buf = [0_u8; 4096];
        let (request_size, client_addr) = match listener.recv_from(&mut request_buf).await {
            Ok(res) => res,
            Err(err) => {
                eprintln!("proxy recv_from error: {err}");
                continue;
            }
        };

        let query = request_buf[..request_size].to_vec();
        let listener_clone = listener.clone();
        
        // Global limit (backpressure)
        let global_permit = match global_semaphore.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                eprintln!("proxy: dropped packet due to extreme global load");
                continue;
            }
        };

        // Per-IP limit (backpressure)
        let ip = client_addr.ip();
        let ip_semaphore = {
            let mut limits = PER_IP_LIMITS.write().await;
            limits.entry(ip).or_insert_with(|| Arc::new(Semaphore::new(MAX_CONCURRENT_PER_IP))).clone()
        };

        spawn(async move {
            let _global_permit = global_permit;
            let _ip_permit = ip_semaphore.acquire().await.ok();
            
            let response = match forward_dns_query(&query, upstream_addr).await {
                Ok(res) => res,
                Err(err) => {
                    eprintln!("proxy forward error: {err}");
                    return;
                }
            };

            if let Err(err) = inspect_and_update_state(&response, client_addr.ip(), stats_ttl).await {
                eprintln!("proxy state update error: {err}");
            }

            if let Err(err) = listener_clone.send_to(&response, client_addr).await {
                eprintln!("proxy send_to error: {err}");
            }
        });
    }
}

async fn forward_dns_query(query: &[u8], upstream_addr: SocketAddr) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
    let upstream = UdpSocket::bind("0.0.0.0:0").await?;
    upstream.send_to(query, upstream_addr).await?;

    let mut response_buf = [0_u8; 4096];
    let result = timeout(Duration::from_secs(5), upstream.recv_from(&mut response_buf)).await;
    
    match result {
        Ok(Ok((response_size, _))) => Ok(response_buf[..response_size].to_vec()),
        Ok(Err(err)) => Err(err.into()),
        Err(_) => Err("upstream dns timeout".into()),
    }
}

async fn inspect_and_update_state(response: &[u8], origin: IpAddr, stats_ttl: Duration) -> Result<(), Box<dyn Error + Send + Sync>> {
    let message = match Message::from_vec(response) {
        Ok(m) => m,
        Err(_) => return Ok(()),
    };
    let resolved_ips = collect_resolved_ips(&message);
    let mut domains = Vec::new();
    for query in &message.queries {
        let domain = query.name().to_utf8().trim_end_matches('.').to_ascii_lowercase();
        record_resolve(&domain, origin, stats_ttl).await;
        domains.push(domain);
    }

    if resolved_ips.is_empty() {
        return Ok(());
    }

    let changed_sets = apply_resolved_ips(&domains, &resolved_ips).await;
    if changed_sets.is_empty() {
        return Ok(());
    }

    for (name, ips) in changed_sets {
        if let Err(err) = update_ipset(name.clone(), ips).await {
            eprintln!("ipset update error for {name}: {err}");
        }
    }

    Ok(())
}

fn collect_resolved_ips(message: &Message) -> Vec<IpAddr> {
    let mut ips = Vec::new();

    for answer in &message.answers {
        match &answer.data {
            RData::A(ipv4) => ips.push(IpAddr::V4((*ipv4).into())),
            RData::AAAA(ipv6) => ips.push(IpAddr::V6((*ipv6).into())),
            _ => {}
        }
    }

    ips
}

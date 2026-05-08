use std::error::Error;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::time::Duration;

use hickory_proto::op::Message;
use hickory_proto::rr::RData;
use tokio::runtime::Builder;

use crate::ipset::update_ipset;
use crate::state;

pub fn run_dns_proxy(
    dns_listen_addr: &str,
    dns_upstream_addr: &str,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let listener = UdpSocket::bind(dns_listen_addr)?;
    let upstream_addr: SocketAddr = dns_upstream_addr.parse()?;
    println!("dockerwall dns proxy listening on {dns_listen_addr}");

    loop {
        let mut request_buf = [0_u8; 4096];
        let (request_size, client_addr) = listener.recv_from(&mut request_buf)?;

        let response = forward_dns_query(&request_buf[..request_size], upstream_addr)?;
        inspect_and_update_state(&response)?;

        listener.send_to(&response, client_addr)?;
    }
}

fn forward_dns_query(query: &[u8], upstream_addr: SocketAddr) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
    let upstream = UdpSocket::bind("0.0.0.0:0")?;
    upstream.set_read_timeout(Some(Duration::from_secs(5)))?;
    upstream.send_to(query, upstream_addr)?;

    let mut response_buf = [0_u8; 4096];
    let (response_size, _) = upstream.recv_from(&mut response_buf)?;
    Ok(response_buf[..response_size].to_vec())
}

fn inspect_and_update_state(response: &[u8]) -> Result<(), Box<dyn Error + Send + Sync>> {
    let message = Message::from_vec(response)?;
    let resolved_ips = collect_resolved_ips(&message);

    if resolved_ips.is_empty() {
        return Ok(());
    }

    let mut domains = Vec::new();
    for query in &message.queries {
        domains.push(query.name().to_utf8().trim_end_matches('.').to_ascii_lowercase());
    }

    let changed_sets = state::apply_resolved_ips(&domains, &resolved_ips);
    if changed_sets.is_empty() {
        return Ok(());
    }

    let runtime = Builder::new_current_thread().build()?;
    for (name, ips) in changed_sets {
        runtime.block_on(update_ipset(name, ips));
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

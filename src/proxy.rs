use std::collections::HashMap;
use std::error::Error;
use std::io::{Error as IoError, ErrorKind, IoSlice, IoSliceMut};
use std::net::{IpAddr, SocketAddr};
use std::os::fd::AsRawFd;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use hickory_proto::op::Message;
use hickory_proto::rr::RData;
use nix::sys::socket::{
    recvmsg, sendmsg, setsockopt, sockopt, ControlMessage, ControlMessageOwned, MsgFlags,
    SockaddrIn,
};
use tokio::io::Interest;
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
    let listener = UdpSocket::bind(dns_listen_addr).await?;
    let receive_packet_info = listener.local_addr()?.is_ipv4();
    if receive_packet_info {
        setsockopt(&listener, sockopt::Ipv4PacketInfo, &true)?;
    }
    let listener = Arc::new(listener);
    let upstream_addr: SocketAddr = dns_upstream_addr.parse()?;
    let global_semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_GLOBAL));
    println!("dockerwall dns proxy listening on {dns_listen_addr}");

    loop {
        let (query, client_addr, reply_source) = match receive_dns_request(&listener, receive_packet_info).await {
            Ok(request) => request,
            Err(err) => {
                eprintln!("proxy recv_from error: {err}");
                continue;
            }
        };

        if !is_local_ip(client_addr.ip()) {
            eprintln!("proxy: dropped packet from non-local IP: {}", client_addr.ip());
            continue;
        }

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

            if let Err(err) = send_dns_response(&listener_clone, &response, client_addr, reply_source).await {
                eprintln!("proxy send_to error: {err}");
            }
        });
    }
}

async fn receive_dns_request(
    listener: &UdpSocket,
    receive_packet_info: bool,
) -> Result<(Vec<u8>, SocketAddr, Option<nix::libc::in_addr>), IoError> {
    if !receive_packet_info {
        let mut request_buf = [0_u8; 4096];
        let (request_size, client_addr) = listener.recv_from(&mut request_buf).await?;
        return Ok((request_buf[..request_size].to_vec(), client_addr, None));
    }

    listener
        .async_io(Interest::READABLE, || {
            let mut request_buf = [0_u8; 4096];
            let mut buffers = [IoSliceMut::new(&mut request_buf)];
            let mut control = nix::cmsg_space!(nix::libc::in_pktinfo);
            let message = recvmsg::<SockaddrIn>(
                listener.as_raw_fd(),
                &mut buffers,
                Some(&mut control),
                MsgFlags::empty(),
            )
            .map_err(IoError::from)?;
            if message.flags.intersects(MsgFlags::MSG_TRUNC | MsgFlags::MSG_CTRUNC) {
                return Err(IoError::new(ErrorKind::InvalidData, "truncated DNS packet"));
            }

            let (request_size, client_addr, reply_source) = {
                let client_addr = message
                    .address
                    .map(SocketAddr::from)
                    .ok_or_else(|| IoError::new(ErrorKind::InvalidData, "DNS packet has no source address"))?;
                let reply_source = message
                    .cmsgs()
                    .map_err(IoError::from)?
                    .find_map(|message| match message {
                        ControlMessageOwned::Ipv4PacketInfo(packet_info) => Some(packet_info.ipi_spec_dst),
                        _ => None,
                    })
                    .ok_or_else(|| IoError::new(ErrorKind::InvalidData, "DNS packet has no destination address"))?;
                (message.bytes, client_addr, reply_source)
            };
            let query = request_buf[..request_size].to_vec();
            Ok((query, client_addr, Some(reply_source)))
        })
        .await
}

async fn send_dns_response(
    listener: &UdpSocket,
    response: &[u8],
    client_addr: SocketAddr,
    reply_source: Option<nix::libc::in_addr>,
) -> Result<(), IoError> {
    let Some(reply_source) = reply_source else {
        listener.send_to(response, client_addr).await?;
        return Ok(());
    };
    let SocketAddr::V4(client_addr) = client_addr else {
        return Err(IoError::new(
            ErrorKind::InvalidInput,
            "IPv4 packet information with an IPv6 client",
        ));
    };

    listener
        .async_io(Interest::WRITABLE, || {
            let packet_info = nix::libc::in_pktinfo {
                ipi_ifindex: 0,
                ipi_spec_dst: reply_source,
                ipi_addr: nix::libc::in_addr { s_addr: 0 },
            };
            let buffers = [IoSlice::new(response)];
            let control = [ControlMessage::Ipv4PacketInfo(&packet_info)];
            sendmsg(
                listener.as_raw_fd(),
                &buffers,
                &control,
                MsgFlags::empty(),
                Some(&SockaddrIn::from(client_addr)),
            )
            .map(|_| ())
            .map_err(IoError::from)
        })
        .await
}

fn is_local_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            ipv4.is_loopback()
                || ipv4.is_private()
                || ipv4.is_link_local()
                || (ipv4.octets()[0] == 198 && matches!(ipv4.octets()[1], 18 | 19))
        }
        IpAddr::V6(ipv6) => {
            ipv6.is_loopback() || ipv6.is_unique_local() || ipv6.is_unicast_link_local()
        }
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

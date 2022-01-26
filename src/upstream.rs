use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU16, AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::{bail, Result};
use tokio::net::UdpSocket;
use tokio::sync::Semaphore;
use tracing::{debug, warn};

use crate::{OP_QUERY, Packet, PacketKind};
use crate::dns::*;

pub struct UpstreamPool {
    servers: Vec<UpstreamServer>,
    preferred: AtomicUsize,
}

impl UpstreamPool {
    pub fn new(servers: Vec<UpstreamServer>) -> Self {
        Self {
            servers,
            preferred: AtomicUsize::new(0),
        }
    }

    pub async fn lookup(&self, question: &Question) -> Option<Packet> {
        if self.servers.is_empty() {
            return None;
        }
        let idx = self.preferred.load(Ordering::Acquire) % self.servers.len();
        if let Some(r) = self.servers[idx].lookup(question).await {
            match r.response_code {
                | RCODE_NO_ERROR
                | RCODE_NX_DOMAIN
                => return Some(r),
                _ => {}
            }
        }
        let _ = self.preferred.compare_exchange(
            idx,
            idx + 1,
            Ordering::Release,
            Ordering::Relaxed);
        None
    }
}

pub struct UpstreamServer {
    addr: SocketAddr,
    next_packet_id: AtomicU16,
    in_flight: Semaphore,
}

impl UpstreamServer {
    pub fn new(addr: SocketAddr, max_in_flight: usize) -> Self {
        Self {
            addr,
            in_flight: Semaphore::new(max_in_flight),
            next_packet_id: AtomicU16::new(1),
        }
    }

    #[tracing::instrument(skip_all, fields(upstream = ?self.addr))]
    async fn lookup(&self, question: &Question) -> Option<Packet> {
        let _session = self.in_flight.acquire();
        match self.lookup0(question).await {
            Ok(v) => Some(v),
            Err(err) => {
                warn!(?err, "upstream lookup error");
                None
            }
        }
    }

    async fn lookup0(&self, question: &Question) -> Result<Packet> {
        let sock = UdpSocket::bind(&[
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        ][..]).await?;

        let mut query = Packet::new(
            self.next_packet_id.fetch_add(1, Ordering::Relaxed),
            PacketKind::Query,
            OP_QUERY,
            question.clone());
        query.recursion_desired = true;

        let mut buf = Vec::new();
        query.encode(&mut buf);
        debug!(?query, len = buf.len(), "sending query");
        sock.send_to(&buf, self.addr).await?;

        let mut buf = [0; 512];
        let len = tokio::select! {
            r = sock.recv_from(&mut buf) => {
                let (len, _) = r?;
                debug!(?len, "received response");
                len
            }
            _ = tokio::time::sleep(Duration::from_secs(3)) => bail!("timeout"),
        };
        let r = Packet::decode(&buf[..len])?;
        debug!(?r, "decoded response");
        if r.id != query.id {
            bail!("received response with a different id: expected {} got {}", query.id, r.id);
        }
        Ok(r)
    }
}
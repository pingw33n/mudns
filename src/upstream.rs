use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::{bail, Result};
use futures::{future, FutureExt, stream_select, StreamExt, TryStreamExt};
use futures::stream::FuturesUnordered;
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, RwLock, Semaphore};
use tracing::{debug, info, warn};

use crate::{OP_QUERY, Packet, PacketKind};
use crate::dns::*;

pub struct UpstreamPool {
    servers: Vec<Arc<UpstreamServer>>,
    preferred: RwLock<(usize, usize)>,
}

impl UpstreamPool {
    pub fn new(servers: impl IntoIterator<Item=UpstreamServer>) -> Self {
        Self {
            servers: servers.into_iter().map(Arc::new).collect(),
            preferred: Default::default(),
        }
    }

    pub async fn lookup(&self, question: &Question) -> Option<Packet> {
        if self.servers.is_empty() {
            return Some(err_response(RCODE_SERVER_FAILURE, question.clone()));
        }

        loop {
            let ver = {
                let (idx, ver) = *self.preferred.read().await;
                if ver > 0 {
                    let server = &self.servers[idx];
                    if let Some(r) = Self::lookup0(server, question).await {
                        return Some(r);
                    }
                }
                ver
            };
            {
                let (ref mut new_idx, ref mut new_ver) = *self.preferred.write().await;

                if *new_ver == ver {
                    info!("finding the fastest working upstream server");
                    let r = futures::stream::iter(self.servers.iter().enumerate())
                        .map(Ok)
                        .try_for_each_concurrent(None, |(idx, server)| async move {
                            if let Some(r) = Self::lookup0(server, question).await {
                                // Break the for_each
                                Err((idx, r))
                            } else {
                                // Go on.
                                Ok(())
                            }
                        }).await;
                    return Some(match r {
                        Ok(()) => {
                            warn!("all upstreams failed");
                            *new_ver = 0;
                            err_response(RCODE_SERVER_FAILURE, question.clone())
                        }
                        Err((idx, r)) => {
                            *new_idx = idx;
                            *new_ver += 1;
                            info!(idx=*new_idx, ver=*new_ver, "set new preferred server");
                            r
                        }
                    })
                }
            }
        }
    }

    async fn lookup0(server: &UpstreamServer, question: &Question) -> Option<Packet> {
        match server.lookup(question).await {
            Ok(r) => match r.response_code {
                | RCODE_NO_ERROR
                | RCODE_NX_DOMAIN
                => Some(r),
                _ => {
                    warn!(?server.addr, ?r.response_code, "upstream lookup error");
                    None
                }
            }
            Err(err) => {
                warn!(?server.addr, ?err, "upstream lookup error");
                None
            }
        }
    }
}

pub struct UpstreamServer {
    addr: SocketAddr,
    timeout: Duration,
    next_packet_id: AtomicU16,
    in_flight: Semaphore,
}

impl UpstreamServer {
    pub fn new(addr: SocketAddr, timeout: Duration, max_in_flight: usize) -> Self {
        Self {
            addr,
            timeout,
            in_flight: Semaphore::new(max_in_flight),
            next_packet_id: AtomicU16::new(1),
        }
    }

    #[tracing::instrument(skip_all, fields(upstream = ?self.addr))]
    async fn lookup(&self, question: &Question) -> Result<Packet> {
        let _session = self.in_flight.acquire();

        // FIXME this is not working as expected, bind() will create socket for the first addr only.
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
            _ = tokio::time::sleep(self.timeout) => bail!("timeout"),
        };
        let r = Packet::decode(&buf[..len])?;
        debug!(?r, "decoded response");
        if r.id != query.id {
            bail!("received response with a different id: expected {} got {}", query.id, r.id);
        }
        Ok(r)
    }
}

fn err_response(code: ResponseCode, question: Question) -> Packet {
    let mut r = Packet::new(0, PacketKind::Response, OP_QUERY, question.clone());
    r.response_code = code;
    r
}
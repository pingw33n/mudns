use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{bail, Result};
use tokio::net::UdpSocket;
use tokio::sync::{broadcast, Mutex, oneshot, RwLock};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, debug_span, error, info};

use crate::dns::{Packet, PacketKind, RCODE_SERVER_FAILURE};
use crate::process::Processor;

const MAX_UDP_PACKET_LEN: usize = 4096;

#[derive(Clone)]
pub struct Server(Arc<Serveri>);

impl Server {
    pub async fn start(addrs: &[SocketAddr], processor: Processor) -> Result<Self> {
        let sock = Arc::new(UdpSocket::bind(addrs).await?);
        info!("listening {:?}", addrs);

        let (stop_tx, mut stop_rx) = mpsc::channel(1);
        let mut int = Arc::new(Serveri {
            receiver: Mutex:: new(Receiver {
                stop: stop_tx,
            })
        });
        tokio::spawn(clone!(int => async move {
            let mut buf = [0; MAX_UDP_PACKET_LEN];
            loop {
                tokio::select! {
                    r = sock.recv_from(&mut buf) => {
                        match r {
                            Ok((len, src)) => tokio::spawn(clone!(buf, sock, processor => async move {
                                received(src,
                                    buf,
                                    len,
                                    sock,
                                    processor).await
                            })),
                            Err(err) => {
                                error!(?err, "error reading from socket");
                                break;
                            }
                        }
                    }
                    _ = stop_rx.recv() => {
                        break;
                    }
                };
            }
        }));
        Ok(Self(int))
    }
}

struct Serveri {
    receiver: Mutex<Receiver>,
}

struct Receiver {
    stop: mpsc::Sender<()>,
}

#[tracing::instrument(skip_all, fields(?src))]
async fn received(
    src: SocketAddr,
    mut buf: [u8; MAX_UDP_PACKET_LEN],
    len: usize,
    sock: Arc<UdpSocket>,
    processor: Processor,
) {
    debug!(len, "received bytes");

    match decode_and_process(&buf[..len], processor).await {
        Ok(Some(resp)) => {
            let mut buf = Vec::new(); // TODO can use static buf
            resp.encode(&mut buf);
            if let Err(err) = sock.send_to(&buf, src).await {
                error!(?err, "error sending response");
            } else {
                debug!(len = buf.len(), "sent bytes");
            }
        }
        Ok(None) => debug!("no response produced"),
        Err(err) => error!(?err),
    }
}

async fn decode_and_process(msg: &[u8], processor: Processor) -> Result<Option<Packet>> {
    let query = match Packet::decode(msg) {
        Ok(v) => v,
        Err(err) => return Err(err.context("error decoding packet")),
    };
    debug!(?query, "decoded");
    processor.process(query).await
}
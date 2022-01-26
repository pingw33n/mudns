#![deny(unused_must_use)]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tokio::net::UdpSocket;

use crate::cache::Cache;
use crate::dns::{OP_QUERY, Packet, PacketKind, RCODE_NX_DOMAIN};
use crate::process::Processor;
use crate::process::rule::{Action, ActionResult, any, Context, DEFAULT_RULE_LIST_ID, Rule};
use crate::server::Server;
use crate::upstream::{UpstreamPool, UpstreamServer};

#[macro_use]
mod macros;

mod dns;
mod server;
mod process;
mod cache;
mod upstream;

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    tracing_subscriber::fmt::init();

    // foo().await.unwrap();

    struct Nxdomain;

    #[async_trait::async_trait]
    impl Action for Nxdomain {
        async fn apply(&self, ctx: &mut Context) -> Result<ActionResult> {
            let mut packet = ctx.query.to_response();
            packet.response_code = RCODE_NX_DOMAIN;
            Ok(ActionResult::Return(Some(packet)))
        }
    }

    let upool = Arc::new(UpstreamPool::new(vec![
        UpstreamServer::new("8.8.8.8:53".parse().unwrap(), 100),
        UpstreamServer::new("1.1.1.1:53".parse().unwrap(), 100),
    ]));

    let cache = Arc::new(Cache::new(
        100,
        0,
        3600 * 24,
        60,
        Duration::from_secs(3600 * 24),
        5));

    let mut rule_lists = HashMap::new();
    rule_lists.insert(DEFAULT_RULE_LIST_ID.to_owned(), vec![
        Rule {
            matcher: Box::new(any()),
            action: process::rule::forward::forward(upool.clone(), Some(cache)),
        }
    ]);

    let pr = Processor::new(rule_lists);
    let s = Server::start(&["0.0.0.0:53".parse().unwrap()], pr).await.unwrap();
    tokio::time::sleep(Duration::from_secs(10000)).await;
}

async fn foo() -> Result<()> {
    use crate::dns::*;
    let socket = UdpSocket::bind("0.0.0.0:0").await.unwrap();
    socket.connect("8.8.8.8:53").await.unwrap();

    let msg = Packet {
        id: 1,
        kind: PacketKind::Query,
        op_kind: OP_QUERY,
        authoritative: false,
        truncated: false,
        recursion_desired: true,
        recursion_available: false,
        response_code: 0,
        question: Question {
            name: "google.com".parse().unwrap(),
            kind: RRK_A,
            class: RRC_IN,
        },
        answers: vec![],
        authorities: vec![],
        additional_rrs: vec![]
    };

    let mut b = Vec::new();
    msg.encode(&mut b);

    dbg!(&b[..]);
    socket.send(&b).await.unwrap();

    let mut b = [0; 1024];
    let len = socket.recv(&mut b).await.unwrap();

    let msg = Packet::decode(&b[..len]).unwrap();
    dbg!(msg);

    Ok(())
}

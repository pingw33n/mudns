use std::collections::{HashMap, HashSet};
use std::collections::hash_map::Entry;
use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use parking_lot::Mutex;
use tokio::sync::Semaphore;
use tracing::{debug, warn};

use crate::Cache;
use crate::cache::Item;
use crate::dns::*;
use crate::upstream::UpstreamPool;

use super::*;

struct Forward {
    upstream_pool: Arc<UpstreamPool>,
    cache: Option<Arc<Cache>>,
    in_flight: Mutex<HashMap<Question, Arc<Semaphore>>>,
}

impl Forward {
    fn lookup_cache(&self, ctx: &Context) -> Option<Packet> {
        let cache = if let Some(v) = self.cache.as_ref() {
            v
        } else {
            return None;
        };
        let now = Instant::now();

        let mut r = ctx.query.to_response();

        let items = cache.get(
            &ctx.query.question.name,
            ctx.query.question.kind,
            ctx.query.question.class,
            now,
            false);

        for item in items {
            match item {
                Item::Negative { response_code, .. } => r.response_code = response_code,
                Item::Positive(rr) => r.answers.push(rr),
            }
        }

        self.lookup_related(&mut r, cache, now);

        if r.response_code == RCODE_NO_ERROR && r.answers.is_empty() && r.authorities.is_empty() {
            return None;
        }

        debug!(?r, "found in cache");
        Some(r)
    }

    fn lookup_related(&self,
        r: &mut Packet,
        cache: &Cache,
        now: Instant,
    ) {
        if !matches!(r.question.kind, RRK_A | RRK_AAAA)  {
            return;
        }
        if !r.answers.is_empty() {
            return;
        }

        let mut seen = HashSet::new();
        let mut name = r.question.name.clone();
        loop {
            if !seen.insert(name.clone()) {
                warn!(?seen, %name, "CNAME cycle detected");
                r.response_code = RCODE_SERVER_FAILURE;
                return;
            }
            let mut cnames = cache.get(
                &name,
                RRK_CNAME,
                r.question.class,
                now,
                false);
            if cnames.is_empty() {
                break;
            }
            assert_eq!(cnames.len(), 1);
            let cname = cnames.remove(0);
            debug!(%name, ?cname, "found related CNAME RR");
            match cname {
                Item::Negative { response_code, .. } => {
                    if r.response_code == RCODE_NO_ERROR {
                        r.response_code = response_code;
                    }
                    break;
                }
                Item::Positive(rr) => {
                    name = rr.data.as_name().unwrap().clone();
                    r.answers.push(rr);
                }
            }
        }
        let mut has_specific_answer = false;
        if r.response_code == RCODE_NO_ERROR && seen.len() > 1 {
            let items = cache.get(
                &name,
                r.question.kind,
                r.question.class,
                now,
                false);
            for item in items {
                match item {
                    Item::Negative { response_code, .. } => r.response_code = response_code,
                    Item::Positive(rr) => {
                        has_specific_answer = true;
                        r.answers.push(rr);
                    }
                }
            }
        }
        if !has_specific_answer {
            let name = name.parent();
            let items = cache.get(
                &name,
                RRK_SOA,
                r.question.class,
                now,
                false);
            for item in items {
                match item {
                    Item::Negative { .. } => {},
                    Item::Positive(rr) => r.authorities.push(rr),
                }
            }
        }
    }

    fn update_cache(&self, pkt: &Packet) {
        let cache = if let Some(v) = self.cache.as_ref() {
            v
        } else {
            return;
        };
        debug!("caching the response");
        let now = Instant::now();
        for rr in pkt.resource_records() {
            cache.insert(
                rr.name.clone(),
                rr.kind,
                rr.class,
                rr.ttl_secs,
                now,
                Item::Positive(rr.clone()));
        }
        match pkt.response_code {
            | RCODE_SERVER_FAILURE
            | RCODE_NX_DOMAIN
            => {
                let soa = pkt.authorities.get(0)
                    .filter(|rr| rr.kind == RRK_SOA && rr.class == pkt.question.class)
                    .cloned();
                cache.insert(
                    pkt.question.name.clone(),
                    pkt.question.kind,
                    pkt.question.class,
                    soa.as_ref()
                        .map(|rr| rr.ttl_secs.min(rr.data.as_soa().unwrap().min_ttl_secs))
                        .unwrap_or(0),
                    now,
                    Item::Negative {
                        response_code: pkt.response_code,
                        soa: soa.map(|rr| rr.name),
                    });
            }
            _ => {}
        }
    }
}

#[async_trait]
impl Action for Forward {
    async fn apply(&self, ctx: &mut Context) -> Result<ActionResult> {
        if !ctx.query.recursion_desired {
            return Ok(ActionResult::Return(Some(ctx.query.to_response_with_code(RCODE_SERVER_FAILURE))));
        }

        let sema = if self.cache.is_some() {
            if let Some(pkt) = self.lookup_cache(&ctx) {
                return Ok(ActionResult::Return(Some(pkt)));
            }

            let (sema, pending) = match self.in_flight.lock().entry(ctx.query.question.clone()) {
                Entry::Occupied(e) => (e.get().clone(), true),
                Entry::Vacant(e) => (e.insert(Arc::new(Semaphore::new(0))).clone(), false),
            };
            if pending {
                let _ = sema.acquire().await;
                if let Some(pkt) = self.lookup_cache(&ctx) {
                    return Ok(ActionResult::Return(Some(pkt)));
                }
                None
            } else {
                Some(sema)
            }
        } else {
            None
        };

        let mut packet = self.upstream_pool.lookup(&ctx.query.question).await;

        if let Some(pkt) = &mut packet {
            pkt.id = ctx.query.id;
            self.update_cache(pkt);
        }

        if let Some(sema) = sema {
            assert!(self.in_flight.lock().remove(&ctx.query.question).is_some());
            sema.add_permits(usize::MAX >> 3);
        }

        Ok(ActionResult::Return(packet))
    }
}

pub fn forward(upstream_pool: Arc<UpstreamPool>, cache: Option<Arc<Cache>>) -> Box<dyn Action> {
    Box::new(Forward {
        upstream_pool,
        cache,
        in_flight: Default::default(),
    })
}
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use parking_lot::Mutex;
use tokio::sync::{Mutex as AsyncMutex, Semaphore};
use tracing::debug;

use crate::Cache;
use crate::cache::{Item, ItemData};
use crate::dns::{Question, RCODE_NO_ERROR, RCODE_SERVER_FAILURE, ResponseCode};
use crate::upstream::UpstreamPool;

use super::*;

struct Forward {
    upstream_pool: Arc<UpstreamPool>,
    cache: Option<Arc<Cache>>,
    in_flight: Mutex<HashMap<Question, Arc<Semaphore>>>,
}

impl Forward {
    fn lookup_cache(&self, ctx: &Context) -> Option<Packet> {
        let cached_items = if let Some(cache) = self.cache.as_ref() {
            cache.get(
                &ctx.query.question.name,
                ctx.query.question.kind,
                ctx.query.question.class,
                Instant::now(),
                false)
        } else {
            return None;
        };
        if cached_items.is_empty() {
            return None;
        }
        debug!(?cached_items, "found in cache");
        if cached_items.len() == 1 {
            match &cached_items[0] {
                &ItemData::Negative(rc) => return Some(ctx.query.to_response_with_code(rc)),
                ItemData::Positive(_) => {}
            }
        }
        let mut r = ctx.query.to_response();
        for item in cached_items {
            match item {
                ItemData::Negative(_) => {}
                ItemData::Positive(rr) => {
                    if rr.kind == ctx.query.question.kind {
                        r.answers.push(rr);
                    } else {
                        r.additional_rrs.push(rr);
                    }
                }
            }
        }
        Some(r)
    }

    fn update_cache(&self, pkt: &Packet) {
        let cache = if let Some(v) = self.cache.as_ref() {
            v
        } else {
            return;
        };
        debug!("caching the response");
        if pkt.response_code == RCODE_NO_ERROR {
            for rr in &pkt.answers {
                cache.insert(pkt.question.name.clone(), rr.kind, rr.class, Item {
                    ts: Instant::now(),
                    data: ItemData::Positive(rr.clone()),
                });
            }
        } else {
            cache.insert(pkt.question.name.clone(), pkt.question.kind, pkt.question.class, Item {
                ts: Instant::now(),
                data: ItemData::Negative(pkt.response_code),
            });
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
            pkt.remove_unknown_rrs();
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
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Instant;

use anyhow::{bail, Result};
use async_trait::async_trait;
use linked_hash_set::LinkedHashSet;
use tracing::{debug, debug_span};

use crate::cache::{Cache, Item, ItemData};
use crate::dns::*;
use crate::process::rule::*;

pub mod rule;

#[derive(Clone)]
pub struct Processor(Arc<ProcessorInt>);

impl Processor {
    pub fn new(
        rule_lists: HashMap<RuleListId, Vec<Rule>>,
    ) -> Self {
        assert!(rule_lists.contains_key(DEFAULT_RULE_LIST_ID));
        Self(Arc::new(ProcessorInt {
            rule_lists,
        }))
    }

    pub async fn process(&self, mut query: Packet) -> Result<Option<Packet>> {
        if query.kind != PacketKind::Query || query.op_kind != OP_QUERY {
            debug!("not a standard query");
            return Ok(None);
        }
        if query.question.class != RRC_IN {
            debug!("not IN class");
            return Ok(None);
        }

        query.authoritative = false;
        query.truncated = false;
        query.recursion_available = false;
        query.response_code = RCODE_NO_ERROR;
        query.additional_rrs.clear();
        query.answers.clear();
        query.authorities.clear();
        query.additional_rrs.clear();

        let mut rule_list_id = Cow::from(DEFAULT_RULE_LIST_ID);
        let mut rule_list = &self.0.rule_lists[DEFAULT_RULE_LIST_ID];

        let mut seen = LinkedHashSet::new();
        seen.insert(rule_list_id.clone());

        let mut ctx = Context {
            query,
        };
        let resp = 'outer: loop {
            for (rule_idx, rule) in rule_list.iter().enumerate() {
                // TODO use tracing span for rule
                let r = rule.matcher.matches(&ctx).await;
                debug!("rule '{}'.{} match executed: {:?}", rule_list_id, rule_idx, r);
                if r? {
                    let r = rule.action.apply(&mut ctx).await;
                    debug!("rule '{}'.{} applied: {:?}", rule_list_id, rule_idx, r);
                    match r? {
                        ActionResult::Continue => {}
                        ActionResult::Return(resp) => break 'outer resp,
                        ActionResult::RuleList(rl) => {
                            if !seen.insert(rule_list_id.clone().into()) {
                                bail!("rule list cycle detected: {:?} -> '{}'", seen, rl);
                            }
                            rule_list = &self.0.rule_lists[&rl];
                            continue 'outer;
                        }
                    }
                }
            }
            break None;
        };

        if let Some(pkt) = resp.as_ref() {
            assert_eq!(pkt.id, ctx.query.id);
        }

        Ok(resp)
    }
}

struct ProcessorInt {
    rule_lists: HashMap<RuleListId, Vec<Rule>>,
}
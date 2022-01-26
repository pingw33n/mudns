use anyhow::Result;
use async_trait::async_trait;

use crate::dns::Packet;

pub mod forward;

pub type RuleListId = String;
pub type RuleListIdRef<'a> = &'a str;

pub const DEFAULT_RULE_LIST_ID: RuleListIdRef = "default";

#[async_trait]
pub trait Matcher: Send + Sync {
    async fn matches(&self, ctx: &Context) -> Result<bool>;
}

#[derive(Debug)]
pub enum ActionResult {
    Continue,
    Return(Option<Packet>),
    RuleList(RuleListId),
}

#[async_trait]
pub trait Action: Send + Sync {
    async fn apply(&self, ctx: &mut Context) -> Result<ActionResult>;
}

pub struct Context {
    pub query: Packet,
}

pub struct Rule {
    pub matcher: Box<dyn Matcher>,
    pub action: Box<dyn Action>,
}

pub fn any() -> impl Matcher {
    struct Any;

    #[async_trait]
    impl Matcher for Any {
        async fn matches(&self, _ctx: &Context) -> Result<bool> {
            Ok(true)
        }
    }

    Any
}
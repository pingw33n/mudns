use std::borrow::Borrow;
use std::collections::{Bound, BTreeMap, VecDeque};
use std::hash::Hash;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::ops::RangeBounds;
use std::sync::Arc;
use std::time::{Duration, Instant};

use linked_hash_set::LinkedHashSet;
use parking_lot::Mutex;

use lru::LruCache;

use crate::dns::*;

mod lru;

#[derive(Debug, Eq, Clone, Hash, Ord, PartialEq, PartialOrd)]
struct Key {
    name: Name,
    rr_kind: RRKind,
    rr_class: RRClass,
    sub: SubKey,
}

#[derive(Debug, Eq, Clone, Hash, Ord, PartialEq, PartialOrd)]
enum SubKey {
    First,
    Ipv4Addr(Ipv4Addr),
    Ipv6Addr(Ipv6Addr),
    Name(Name),
    Last,
}

#[derive(Clone, Debug)]
pub struct Item {
    pub ts: Instant,
    pub data: ItemData,
}

#[derive(Clone, Debug)]
pub enum ItemData {
    Negative(ResponseCode),
    Positive(ResourceRecord),
}

pub struct Cache {
    cache: Mutex<LruCache<Key, Item>>,
    min_positive_ttl_secs: u32,
    max_positive_ttl_secs: u32,
    negative_ttl_secs: u32,
    max_staleness: Duration,
    stale_ttl_secs: u32,
}

impl Cache {
    pub fn new(
        capacity: usize,
        min_positive_ttl_secs: u32,
        max_positive_ttl_secs: u32,
        negative_ttl_secs: u32,
        max_staleness: Duration,
        stale_ttl_secs: u32,
    ) -> Self {
        Self {
            cache: Mutex::new(LruCache::new(capacity)),
            min_positive_ttl_secs,
            max_positive_ttl_secs,
            negative_ttl_secs,
            max_staleness,
            stale_ttl_secs,
        }
    }

    pub fn get(&self,
        name: &Name,
        rr_kind: RRKind,
        rr_class: RRClass,
        now: Instant,
        include_stale: bool,
    ) -> Vec<ItemData> {
        let start = Key {
            name: name.clone(),
            rr_kind,
            rr_class,
            sub: SubKey::First,
        };
        let mut end = start.clone();
        end.sub = SubKey::Last;

        let mut r = Vec::new();

        let mut cache = self.cache.lock();
        cache.range((Bound::Included(&start), Bound::Included(&end)), true, |_, item| {
            let ttl = match &item.data {
                ItemData::Negative(_) => self.negative_ttl_secs,
                ItemData::Positive(rr) => rr.ttl_secs,
            };
            let expires = item.ts + Duration::from_secs(ttl.into());
            if include_stale && expires + self.max_staleness > now ||
                !include_stale && expires > now
            {
                let mut item_data = item.data.clone();
                match &mut item_data {
                    ItemData::Negative(_) => {}
                    ItemData::Positive(v) => {
                        let elapsed_ttl = (now - item.ts).as_secs()
                            .try_into()
                            .unwrap_or(u32::MAX);
                        v.ttl_secs = v.ttl_secs.checked_sub(elapsed_ttl)
                            .unwrap_or(self.stale_ttl_secs);
                    }
                }
                r.push(item_data.clone());
            }
        });
        r
    }

    pub fn insert(&self,
        name: Name,
        rr_kind: RRKind,
        rr_class: RRClass,
        item: Item,
    ) {
        let sub = if rr_kind == RRK_A || rr_kind == RRK_AAAA || rr_kind == RRK_NS {
            match &item.data {
                ItemData::Negative(_) => SubKey::First,
                ItemData::Positive(rr) => match &rr.data {
                    &RRData::Ipv4Addr(v) => SubKey::Ipv4Addr(v),
                    &RRData::Ipv6Addr(v) => SubKey::Ipv6Addr(v),
                    RRData::Name(v) => SubKey::Name(v.clone()),
                    | RRData::Soa(_)
                    | RRData::Unknown
                    => SubKey::First
                }
            }
        } else {
            SubKey::First
        };
        let key = Key {
            name,
            rr_kind,
            rr_class,
            sub,
        };

        let mut cache = self.cache.lock();
        cache.insert(key, item);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_ordering() {
        fn key(sub: SubKey) -> Key {
            Key {
                name: Name::default(),
                rr_kind: 0,
                rr_class: 0,
                sub,
            }
        }

        let data = [
            SubKey::First,
            SubKey::Ipv4Addr(Ipv4Addr::UNSPECIFIED),
            SubKey::Ipv6Addr(Ipv6Addr::UNSPECIFIED),
            SubKey::Name(Name::default()),
        ];
        for v in data {
            assert!(v < SubKey::Last);
            assert!(key(v) < key(SubKey::Last));
        }
    }
}
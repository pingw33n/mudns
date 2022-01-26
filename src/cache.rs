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
    Negative,
    RRData(crate::dns::RRData),
    Last,
}

#[derive(Clone, Debug)]
struct Value {
    pub ts: Instant,
    pub rcode_or_ttl_secs: u32,
}

#[derive(Clone, Debug)]
pub enum Item {
    Negative(ResponseCode),
    Positive(ResourceRecord),
}

pub struct Cache {
    cache: Mutex<LruCache<Key, Value>>,
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
    ) -> Vec<Item> {
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
        cache.range((Bound::Included(&start), Bound::Included(&end)), true, |key, value| {
            let ttl_secs = match &key.sub {
                SubKey::Negative => self.negative_ttl_secs,
                SubKey::RRData(_) => value.rcode_or_ttl_secs,
                SubKey::First | SubKey::Last => unreachable!(),
            };
            let expires = value.ts + Duration::from_secs(ttl_secs.into());
            if include_stale && expires + self.max_staleness > now ||
                !include_stale && expires > now
            {
                let item = match &key.sub {
                    SubKey::Negative => Item::Negative(value.rcode_or_ttl_secs.try_into().unwrap()),
                    SubKey::RRData(rr) => {
                        let elapsed_ttl_secs = (now - value.ts).as_secs()
                            .try_into()
                            .unwrap_or(u32::MAX);
                        let ttl_secs = value.rcode_or_ttl_secs.checked_sub(elapsed_ttl_secs)
                            .unwrap_or(self.stale_ttl_secs);
                        Item::Positive(ResourceRecord {
                            name: name.clone(),
                            kind: rr_kind,
                            class: rr_class,
                            ttl_secs,
                            data: rr.clone(),
                        })
                    }
                    SubKey::First | SubKey::Last => unreachable!(),
                };
                r.push(item);
            }
        });
        r
    }

    pub fn insert(&self,
        name: Name,
        rr_kind: RRKind,
        rr_class: RRClass,
        now: Instant,
        item: Item,
    ) {
        let (sub, rcode_or_ttl_secs) = match item {
            Item::Negative(rcode) => (SubKey::Negative, rcode.into()),
            Item::Positive(rr) => (SubKey::RRData(rr.data), rr.ttl_secs),
        };
        let key = Key {
            name,
            rr_kind,
            rr_class,
            sub,
        };

        let mut cache = self.cache.lock();
        cache.insert(key, Value {
            ts: now,
            rcode_or_ttl_secs,
        });
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
            SubKey::Negative,
            SubKey::RRData(RRData::Name("abc.def".parse().unwrap())),
            SubKey::RRData(RRData::Ipv4Addr(Ipv4Addr::UNSPECIFIED)),
            SubKey::RRData(RRData::Ipv6Addr(Ipv6Addr::UNSPECIFIED)),
        ];
        for v in data {
            assert!(v < SubKey::Last);
            assert!(key(v) < key(SubKey::Last));
        }
    }
}
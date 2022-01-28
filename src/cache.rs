use std::collections::{Bound, HashSet};
use std::hash::Hash;
use std::time::{Duration, Instant};

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
    Unique,
    RRData(crate::dns::RRData),
    Last,
}

#[derive(Clone, Debug)]
struct Value {
    pub ts: Instant,
    pub ttl_secs: u32,
    pub response_code: ResponseCode,
    pub rr_data: Option<RRData>,
    pub authorities: Vec<ResourceRecord>,
}

#[derive(Clone, Debug)]
pub enum Item {
    Negative {
        response_code: ResponseCode,
        // TODO optimize: store name(s) of SOA RRs
        authorities: Vec<ResourceRecord>,
    },
    Positive(ResourceRecord),
}

pub struct Cache {
    cache: Mutex<LruCache<Key, Value>>,
    max_ttl_secs: u32,
    min_positive_ttl_secs: u32,
    min_negative_ttl_secs: u32,
    max_staleness: Duration,
    stale_ttl_secs: u32,
}

impl Cache {
    pub fn new(
        capacity: usize,
        max_ttl_secs: u32,
        min_positive_ttl_secs: u32,
        min_negative_ttl_secs: u32,
        max_staleness: Duration,
        stale_ttl_secs: u32,
    ) -> Self {
        assert!(max_ttl_secs >= min_positive_ttl_secs);
        assert!(max_ttl_secs >= min_negative_ttl_secs);
        Self {
            cache: Mutex::new(LruCache::new(capacity)),
            max_ttl_secs,
            min_positive_ttl_secs,
            min_negative_ttl_secs,
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
        cache.range((Bound::Excluded(&start), Bound::Excluded(&end)), true, |key, value| {
            let expires = value.ts + Duration::from_secs(value.ttl_secs.into());
            if include_stale && expires + self.max_staleness > now ||
                !include_stale && expires > now
            {
                let item = match &key.sub {
                    SubKey::Unique => {
                        if value.response_code == RCODE_NO_ERROR {
                            self.positive(now, key, value, value.rr_data.as_ref().unwrap())
                        } else {
                            assert!(r.is_empty());
                            assert!(value.rr_data.is_none());
                            Item::Negative {
                                response_code: value.response_code,
                                authorities: value.authorities.clone(),
                            }
                        }
                    }
                    SubKey::RRData(rr_data) => self.positive(now, key, value, rr_data),
                    SubKey::First | SubKey::Last => unreachable!(),
                };
                r.push(item);
            }
        });
        r
    }

    fn positive(&self, now: Instant, key: &Key, value: &Value, rr_data: &RRData) -> Item {
        assert_eq!(value.response_code, RCODE_NO_ERROR);
        assert!(value.authorities.is_empty());
        let elapsed_ttl_secs = (now - value.ts).as_secs()
            .try_into()
            .unwrap_or(u32::MAX);
        let ttl_secs = value.ttl_secs.checked_sub(elapsed_ttl_secs)
            .unwrap_or(self.stale_ttl_secs);
        Item::Positive(ResourceRecord {
            name: key.name.clone(),
            kind: key.rr_kind,
            class: key.rr_class,
            ttl_secs,
            data: rr_data.clone(),
        })
    }

    pub fn insert(&self,
        name: Name,
        rr_kind: RRKind,
        rr_class: RRClass,
        now: Instant,
        item: Item,
    ) {
        let sub;
        let ttl_secs;
        let response_code;
        let authorities;

        let rr_data =match item {
            Item::Negative { response_code: rcode, authorities: auths } => {
                assert_ne!(rcode, RCODE_NO_ERROR);
                sub = SubKey::Unique;
                ttl_secs = auths.get(0)
                    .map(|v| v.ttl_secs.clamp(self.min_negative_ttl_secs, self.max_ttl_secs))
                    .unwrap_or(self.min_negative_ttl_secs);
                response_code = rcode;
                authorities = auths;
                None
            },
            Item::Positive(rr) => {
                ttl_secs = rr.ttl_secs.clamp(self.min_positive_ttl_secs, self.max_ttl_secs);
                response_code = RCODE_NO_ERROR;
                authorities = Vec::new();
                match rr.kind {
                    | RRK_CNAME
                    | RRK_PTR
                    | RRK_SOA
                    => {
                        sub = SubKey::Unique;
                        Some(rr.data)
                    }
                    _ => {
                        sub = SubKey::RRData(rr.data);
                        None
                    }
                }
            }
        };
        if ttl_secs == 0 {
            return;
        }
        let key = Key {
            name: name.clone(),
            rr_kind,
            rr_class,
            sub,
        };

        let mut cache = self.cache.lock();

        // Maintain mutual-exclusivity invariant.
        let remove_kinds = match rr_kind {
            RRK_CNAME => &[RRK_A, RRK_AAAA][..],
            RRK_A => &[RRK_CNAME],
            RRK_AAAA => &[RRK_CNAME],
            _ => &[],
        };
        let mut start = Key {
            name: name.clone(),
            rr_kind: RRK_NULL,
            rr_class,
            sub: SubKey::First,
        };
        let mut end = Key {
            name: name.clone(),
            rr_kind: RRK_NULL,
            rr_class,
            sub: SubKey::Last,
        };
        for &rr_kind in remove_kinds {
            start.rr_kind = rr_kind;
            end.rr_kind = rr_kind;
            cache.remove_range((Bound::Excluded(&start), Bound::Excluded(&end)));
        }

        cache.insert(key, Value {
            ts: now,
            ttl_secs,
            response_code,
            rr_data,
            authorities,
        });
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

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
            SubKey::Unique,
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
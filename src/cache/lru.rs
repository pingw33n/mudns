use std::borrow::Borrow;
use std::collections::BTreeMap;
use std::hash::Hash;
use std::ops::RangeBounds;

use linked_hash_set::LinkedHashSet;

pub struct LruCache<K, V> {
    map: BTreeMap<K, V>,
    order: LinkedHashSet<K>,
    max_len: usize,
}

impl<K, V> LruCache<K, V>
    where
        K: Clone + Eq + Hash + Ord,
{
    pub fn new(max_len: usize) -> Self {
        assert!(max_len > 0);
        Self {
            map: BTreeMap::new(),
            order: LinkedHashSet::new(),
            max_len,
        }
    }

    pub fn range<T: ?Sized, R>(&mut self, range: R, touch: bool, mut f: impl FnMut(&K, &V))
        where
            T: Ord,
            K: Borrow<T>,
            R: RangeBounds<T>,
    {
        for (k, v) in self.map.range(range) {
            if touch {
                Self::touch(&mut self.order, k);
            }
            f(k, v);
        }
    }

    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        while self.map.len() == self.max_len {
            let k = self.order.pop_back().unwrap();
            assert!(self.map.remove(&k).is_some());
        }
        Self::touch(&mut self.order, &key);
        self.map.insert(key, value)
    }

    fn touch(order: &mut LinkedHashSet<K>, key: &K) {
        if !order.refresh(key) {
            order.insert(key.clone());
        }
    }
}
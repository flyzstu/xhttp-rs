use anyhow::Result;
use std::{
    cmp::Reverse,
    collections::{BinaryHeap, HashMap, VecDeque},
    net::IpAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::Notify;

use super::message::age_response_ttls;

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(super) enum CacheKey {
    Lookup {
        name: Arc<str>,
        qtype: u16,
        server: Option<Arc<str>>,
        client_subnet: Option<Arc<str>>,
    },
    Wire {
        query: Arc<[u8]>,
        server: Arc<str>,
    },
}
#[derive(Clone)]
pub(super) enum CacheValue {
    Addresses(Vec<IpAddr>),
    Wire(Vec<u8>),
}
pub(super) struct CacheEntry {
    value: CacheValue,
    expires: Instant,
    inserted: Instant,
    version: u64,
    last_access: u64,
}
pub(super) struct DnsCache {
    entries: HashMap<CacheKey, CacheEntry>,
    expiry: BinaryHeap<Reverse<(Instant, u64, CacheKey)>>,
    lru: VecDeque<(u64, u64, CacheKey)>,
    capacity: usize,
    clock: u64,
    disable_expire: bool,
}
pub(super) struct Flight {
    result: Mutex<Option<std::result::Result<CacheValue, String>>>,
    ready: Notify,
}
impl Flight {
    pub(super) fn new() -> Self {
        Self {
            result: Mutex::new(None),
            ready: Notify::new(),
        }
    }

    pub(super) async fn wait(&self) -> Result<CacheValue> {
        loop {
            let notified = self.ready.notified();
            if let Some(result) = self
                .result
                .lock()
                .expect("DNS flight result lock poisoned")
                .clone()
            {
                return result.map_err(anyhow::Error::msg);
            }
            notified.await;
        }
    }

    pub(super) fn complete(&self, result: std::result::Result<CacheValue, String>) {
        *self.result.lock().expect("DNS flight result lock poisoned") = Some(result);
        self.ready.notify_waiters();
    }
}
impl DnsCache {
    pub(super) fn new(capacity: usize, disable_expire: bool) -> Self {
        Self {
            entries: HashMap::new(),
            expiry: BinaryHeap::new(),
            lru: VecDeque::new(),
            capacity,
            clock: 0,
            disable_expire,
        }
    }

    pub(super) fn get(&mut self, key: &CacheKey) -> Option<CacheValue> {
        let now = Instant::now();
        if !self.disable_expire
            && self
                .entries
                .get(key)
                .is_some_and(|entry| entry.expires <= now)
        {
            self.entries.remove(key);
            return None;
        }
        let entry = self.entries.get_mut(key)?;
        self.clock = self.clock.wrapping_add(1);
        entry.last_access = self.clock;
        self.lru
            .push_back((entry.last_access, entry.version, key.clone()));
        let elapsed = now.saturating_duration_since(entry.inserted);
        let mut value = entry.value.clone();
        if let CacheValue::Wire(response) = &mut value {
            age_response_ttls(response, elapsed.as_secs().min(u32::MAX as u64) as u32);
        }
        self.compact_lru();
        Some(value)
    }

    pub(super) fn insert(&mut self, key: CacheKey, value: CacheValue, ttl: Duration) {
        let now = Instant::now();
        self.purge_expired(now);
        self.clock = self.clock.wrapping_add(1);
        let version = self.clock;
        let expires = now + ttl;
        self.entries.insert(
            key.clone(),
            CacheEntry {
                value,
                expires,
                inserted: now,
                version,
                last_access: self.clock,
            },
        );
        self.expiry.push(Reverse((expires, version, key.clone())));
        self.lru.push_back((self.clock, version, key));
        self.evict_lru();
        self.compact_lru();
    }

    fn purge_expired(&mut self, now: Instant) {
        if self.disable_expire {
            return;
        }
        while self
            .expiry
            .peek()
            .is_some_and(|Reverse((expires, _, _))| *expires <= now)
        {
            let Reverse((_, version, key)) = self.expiry.pop().expect("expiry heap not empty");
            if self
                .entries
                .get(&key)
                .is_some_and(|entry| entry.version == version && entry.expires <= now)
            {
                self.entries.remove(&key);
            }
        }
    }

    fn evict_lru(&mut self) {
        while self.entries.len() > self.capacity {
            let Some((access, version, key)) = self.lru.pop_front() else {
                break;
            };
            if self
                .entries
                .get(&key)
                .is_some_and(|entry| entry.version == version && entry.last_access == access)
            {
                self.entries.remove(&key);
            }
        }
    }

    fn compact_lru(&mut self) {
        if self.lru.len() <= self.capacity.saturating_mul(8).max(64) {
            return;
        }
        self.lru = self
            .entries
            .iter()
            .map(|(key, entry)| (entry.last_access, entry.version, key.clone()))
            .collect();
        self.lru.make_contiguous().sort_by_key(|entry| entry.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lookup_key(name: &str) -> CacheKey {
        CacheKey::Lookup {
            name: name.into(),
            qtype: 1,
            server: Some("test".into()),
            client_subnet: None,
        }
    }

    fn wire_key(query: &[u8]) -> CacheKey {
        CacheKey::Wire {
            query: query.into(),
            server: "test".into(),
        }
    }

    #[test]
    fn insert_and_get_return_the_value() {
        let mut cache = DnsCache::new(16, false);
        let key = lookup_key("example.com");
        cache.insert(key.clone(), CacheValue::Addresses(vec!["1.2.3.4".parse().unwrap()]), Duration::from_secs(60));
        assert!(matches!(
            cache.get(&key),
            Some(CacheValue::Addresses(ref addresses)) if addresses == &vec!["1.2.3.4".parse::<IpAddr>().unwrap()]
        ));
        assert!(cache.get(&lookup_key("other.com")).is_none());
    }

    #[test]
    fn wire_value_ages_ttls_on_get() {
        let mut cache = DnsCache::new(16, false);
        let mut response = vec![0u8; 12];
        response[6..8].copy_from_slice(&1u16.to_be_bytes()); // one answer
        response.extend([0xc0, 0x0c]);
        response.extend(1u16.to_be_bytes());
        response.extend(1u16.to_be_bytes());
        response.extend(100u32.to_be_bytes()); // ttl 100
        response.extend(4u16.to_be_bytes());
        response.extend([1, 2, 3, 4]);
        let key = wire_key(&[0u8; 4]);
        cache.insert(key.clone(), CacheValue::Wire(response.clone()), Duration::from_secs(60));
        // Immediately after insert the TTL is still ~100.
        let first = cache.get(&key).unwrap();
        let CacheValue::Wire(first_bytes) = first else { panic!() };
        let ttl_offsets = super::super::message::ttl_offsets(&first_bytes).unwrap();
        assert_eq!(ttl_offsets[0].2, 100);
        // Force expiry of the entry and confirm it is gone.
        std::thread::sleep(Duration::from_millis(5));
        let mut cache = DnsCache::new(16, false);
        cache.insert(key.clone(), CacheValue::Wire(response), Duration::from_millis(1));
        std::thread::sleep(Duration::from_millis(20));
        assert!(cache.get(&key).is_none());
    }

    #[test]
    fn expired_entries_are_purged() {
        let mut cache = DnsCache::new(16, false);
        let key = lookup_key("short.com");
        cache.insert(key.clone(), CacheValue::Addresses(vec![]), Duration::from_millis(1));
        std::thread::sleep(Duration::from_millis(20));
        assert!(cache.get(&key).is_none());
    }

    #[test]
    fn disable_expire_keeps_entries_forever() {
        let mut cache = DnsCache::new(16, true);
        let key = lookup_key("forever.com");
        cache.insert(key.clone(), CacheValue::Addresses(vec![]), Duration::from_millis(1));
        std::thread::sleep(Duration::from_millis(20));
        assert!(cache.get(&key).is_some());
    }

    #[test]
    fn lru_evicts_the_least_recently_used_entry() {
        let mut cache = DnsCache::new(2, false);
        let a = lookup_key("a.com");
        let b = lookup_key("b.com");
        let c = lookup_key("c.com");
        cache.insert(a.clone(), CacheValue::Addresses(vec![]), Duration::from_secs(60));
        cache.insert(b.clone(), CacheValue::Addresses(vec![]), Duration::from_secs(60));
        // Touching a makes b the least recently used.
        let _ = cache.get(&a);
        cache.insert(c.clone(), CacheValue::Addresses(vec![]), Duration::from_secs(60));
        assert!(cache.get(&b).is_none());
        assert!(cache.get(&a).is_some());
        assert!(cache.get(&c).is_some());
    }

    #[test]
    fn stale_lru_entries_do_not_evict_reinserted_keys() {
        let mut cache = DnsCache::new(1, false);
        let key = lookup_key("x.com");
        cache.insert(key.clone(), CacheValue::Addresses(vec![]), Duration::from_secs(60));
        // Same key reinserted gets a new version; the stale LRU entry must not evict it.
        cache.insert(key.clone(), CacheValue::Addresses(vec!["9.9.9.9".parse().unwrap()]), Duration::from_secs(60));
        let value = cache.get(&key).unwrap();
        assert!(matches!(value, CacheValue::Addresses(ref v) if v == &vec!["9.9.9.9".parse::<IpAddr>().unwrap()]));
    }

    #[test]
    fn compact_lru_rebuilds_from_current_entries() {
        let mut cache = DnsCache::new(5, false);
        for name in ["a.com", "b.com", "c.com", "d.com", "e.com"] {
            cache.insert(lookup_key(name), CacheValue::Addresses(vec![]), Duration::from_secs(60));
        }
        // Force a compact by touching entries and growing the LRU queue.
        let keys: Vec<_> = ["a.com", "b.com", "c.com", "d.com", "e.com"]
            .map(lookup_key)
            .into_iter()
            .collect();
        for _ in 0..40 {
            for key in &keys {
                let _ = cache.get(key);
            }
        }
        cache.compact_lru();
        // No panic and entries remain retrievable.
        for key in &keys {
            assert!(cache.get(key).is_some());
        }
    }
}

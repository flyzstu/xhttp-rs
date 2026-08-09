use anyhow::Result;
use std::{
    cmp::Reverse,
    collections::{BinaryHeap, HashMap, VecDeque},
    net::IpAddr,
    sync::Mutex,
    time::{Duration, Instant},
};
use tokio::sync::Notify;

use super::message::age_response_ttls;

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(super) enum CacheKey {
    Lookup {
        name: String,
        qtype: u16,
        server: Option<String>,
        client_subnet: Option<String>,
    },
    Wire {
        query: Vec<u8>,
        server: String,
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
        self.purge_expired(now);
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

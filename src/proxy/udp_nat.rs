use anyhow::{Result, bail};
use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr},
};
use tokio::sync::mpsc;

/// UDP NAT mapping behavior, matching sing-box `udp_mapping`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UdpNatBehavior {
    EndpointIndependent,
    AddressDependent,
    AddressAndPortDependent,
}

impl UdpNatBehavior {
    pub fn parse(value: Option<&str>, field: &str) -> Result<Self> {
        match value.unwrap_or("endpoint_independent") {
            "endpoint_independent" => Ok(Self::EndpointIndependent),
            "address_dependent" => Ok(Self::AddressDependent),
            "address_and_port_dependent" => Ok(Self::AddressAndPortDependent),
            value => bail!("unsupported UDP NAT {field}: {value}"),
        }
    }
}

pub(crate) type Datagram = (Vec<u8>, SocketAddr, SocketAddr);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum UdpMappingKey {
    Endpoint(SocketAddr),
    Address(SocketAddr, IpAddr),
    AddressAndPort(SocketAddr, SocketAddr),
}

pub(crate) struct UdpNatSession {
    sender: Option<mpsc::Sender<(Vec<u8>, SocketAddr)>>,
    allowed_addresses: HashSet<IpAddr>,
    allowed_endpoints: HashSet<SocketAddr>,
    last_used: std::time::Instant,
    generation: u64,
}

pub(crate) struct UdpNatTable {
    filtering: UdpNatBehavior,
    max_sessions: usize,
    idle_timeout: std::time::Duration,
    generation: u64,
    sessions: HashMap<UdpMappingKey, UdpNatSession>,
}

impl UdpNatTable {
    pub(crate) fn new(
        filtering: UdpNatBehavior,
        max_sessions: usize,
        idle_timeout: std::time::Duration,
    ) -> Self {
        Self {
            filtering,
            max_sessions,
            idle_timeout,
            generation: 0,
            sessions: HashMap::new(),
        }
    }

    pub(crate) fn key_for(
        mapping: UdpNatBehavior,
        source: SocketAddr,
        destination: SocketAddr,
    ) -> UdpMappingKey {
        match mapping {
            UdpNatBehavior::EndpointIndependent => UdpMappingKey::Endpoint(source),
            UdpNatBehavior::AddressDependent => UdpMappingKey::Address(source, destination.ip()),
            UdpNatBehavior::AddressAndPortDependent => {
                UdpMappingKey::AddressAndPort(source, destination)
            }
        }
    }

    /// Combined touch-and-fetch for the hot packet path, avoiding a second
    /// table lock and deferring expiry until the table is at capacity.
    pub(crate) fn touch_and_sender(
        &mut self,
        key: UdpMappingKey,
        destination: SocketAddr,
    ) -> Option<mpsc::Sender<(Vec<u8>, SocketAddr)>> {
        if !self.sessions.contains_key(&key) {
            self.reclaim_if_full();
        }
        self.generation = self.generation.wrapping_add(1);
        let session = self.sessions.entry(key).or_insert_with(|| UdpNatSession {
            sender: None,
            allowed_addresses: HashSet::new(),
            allowed_endpoints: HashSet::new(),
            last_used: std::time::Instant::now(),
            generation: self.generation,
        });
        session.last_used = std::time::Instant::now();
        session.generation = self.generation;
        session.allowed_addresses.insert(destination.ip());
        session.allowed_endpoints.insert(destination);
        session
            .sender
            .as_ref()
            .filter(|sender| !sender.is_closed())
            .cloned()
    }

    /// Only scan for idle entries when the table is at capacity and a new
    /// session is about to be inserted; the hot packet path otherwise skips
    /// the O(sessions) retain.
    fn reclaim_if_full(&mut self) {
        if self.sessions.len() < self.max_sessions {
            return;
        }
        let timeout = self.idle_timeout;
        let before = self.sessions.len();
        self.sessions
            .retain(|_, session| session.last_used.elapsed() < timeout);
        if self.sessions.len() == before && self.sessions.len() >= self.max_sessions {
            self.evict_lru();
        }
    }

    pub(crate) fn insert_sender(
        &mut self,
        key: UdpMappingKey,
        sender: mpsc::Sender<(Vec<u8>, SocketAddr)>,
    ) {
        if let Some(session) = self.sessions.get_mut(&key) {
            session.sender = Some(sender);
        }
    }

    #[cfg(test)]
    pub(crate) fn contains_key(&self, key: &UdpMappingKey) -> bool {
        self.sessions.contains_key(key)
    }

    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    #[cfg(test)]
    pub(crate) fn age_last_used(&mut self, key: UdpMappingKey, duration: std::time::Duration) {
        if let Some(session) = self.sessions.get_mut(&key) {
            let now = std::time::Instant::now();
            if session.last_used.elapsed() < duration {
                session.last_used = now - duration;
            }
        }
    }

    pub(crate) fn clear_sender(&mut self, key: UdpMappingKey) {
        if let Some(session) = self.sessions.get_mut(&key) {
            session.sender = None;
        }
    }

    pub(crate) fn allow_response(&mut self, key: UdpMappingKey, remote: SocketAddr) -> bool {
        self.expire();
        let Some(session) = self.sessions.get_mut(&key) else {
            return false;
        };
        let allowed = match self.filtering {
            UdpNatBehavior::EndpointIndependent => true,
            UdpNatBehavior::AddressDependent => session.allowed_addresses.contains(&remote.ip()),
            UdpNatBehavior::AddressAndPortDependent => session.allowed_endpoints.contains(&remote),
        };
        if allowed {
            self.generation = self.generation.wrapping_add(1);
            session.last_used = std::time::Instant::now();
            session.generation = self.generation;
        }
        allowed
    }

    pub(crate) fn expire(&mut self) {
        let timeout = self.idle_timeout;
        self.sessions
            .retain(|_, session| session.last_used.elapsed() < timeout);
    }

    fn evict_lru(&mut self) {
        if let Some(key) = self
            .sessions
            .iter()
            .min_by_key(|(_, session)| session.generation)
            .map(|(key, _)| *key)
        {
            self.sessions.remove(&key);
        }
    }
}

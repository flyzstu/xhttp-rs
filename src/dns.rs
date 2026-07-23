use anyhow::{Context, Result, bail};
use rand::Rng;
use std::{
    cmp::Reverse,
    collections::{BinaryHeap, HashMap, VecDeque},
    future::Future,
    hash::Hash,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU32, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::{
    net::{TcpStream, UdpSocket},
    sync::{Notify, OnceCell, Semaphore, oneshot},
    time::timeout,
};
use tokio_rustls::TlsConnector;

use crate::singbox::{DnsConfig, DnsRule, DnsServer};

const DNS_TIMEOUT: Duration = Duration::from_secs(5);
const HTTP_TIMEOUT: Duration = Duration::from_secs(8);
const STREAM_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const STREAM_POOL_SIZE: usize = 32;
const MAX_DNS_MESSAGE: usize = u16::MAX as usize;

#[derive(Clone)]
pub struct DnsResolver {
    inner: Arc<Inner>,
}
struct Inner {
    servers: HashMap<String, Arc<Upstream>>,
    rules: Vec<DnsRule>,
    final_tag: String,
    cache: Mutex<DnsCache>,
    flights: Mutex<HashMap<CacheKey, Arc<Flight>>>,
    cache_enabled: bool,
    http: reqwest::Client,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum CacheKey {
    Lookup(String, u16),
    Wire(Vec<u8>),
}

#[derive(Clone)]
enum CacheValue {
    Addresses(Vec<IpAddr>),
    Wire(Vec<u8>),
}

struct CacheEntry {
    value: CacheValue,
    expires: Instant,
    inserted: Instant,
    version: u64,
    last_access: u64,
}

struct DnsCache {
    entries: HashMap<CacheKey, CacheEntry>,
    expiry: BinaryHeap<Reverse<(Instant, u64, CacheKey)>>,
    lru: VecDeque<(u64, u64, CacheKey)>,
    capacity: usize,
    clock: u64,
}

struct Flight {
    result: Mutex<Option<std::result::Result<CacheValue, String>>>,
    ready: Notify,
}

struct Upstream {
    config: DnsServer,
    endpoint: Option<Arc<Endpoint>>,
    udp: OnceCell<Arc<UdpMultiplexer>>,
    stream: Option<TcpPool>,
}

struct Endpoint {
    host: String,
    port: u16,
    address: OnceCell<SocketAddr>,
}

type PendingDatagrams =
    Arc<Mutex<HashMap<u16, oneshot::Sender<std::result::Result<Vec<u8>, String>>>>>;

struct UdpMultiplexer {
    socket: Arc<UdpSocket>,
    pending: PendingDatagrams,
    next_id: AtomicU32,
}

struct TcpPool {
    endpoint: Arc<Endpoint>,
    tls: Option<TlsConnector>,
    idle: Mutex<Vec<IdleConnection>>,
    permits: Arc<Semaphore>,
}

struct IdleConnection {
    stream: Box<dyn DnsIo>,
    last_used: Instant,
}

impl DnsResolver {
    pub fn new(config: &DnsConfig) -> Result<Self> {
        crate::install_crypto_provider();
        let dot_tls = if config.servers.iter().any(|server| server.r#type == "tls") {
            let mut roots = rustls::RootCertStore::empty();
            let native = rustls_native_certs::load_native_certs();
            for certificate in native.certs {
                roots
                    .add(certificate)
                    .context("add native DNS root certificate")?;
            }
            Some(TlsConnector::from(Arc::new(
                rustls::ClientConfig::builder()
                    .with_root_certificates(roots)
                    .with_no_client_auth(),
            )))
        } else {
            None
        };
        let mut servers = HashMap::new();
        for server in &config.servers {
            servers.insert(
                server.tag.clone(),
                Arc::new(Upstream::new(server.clone(), dot_tls.clone())?),
            );
        }
        let final_tag = config
            .final_server
            .clone()
            .or_else(|| config.servers.first().map(|s| s.tag.clone()))
            .context("DNS requires a server")?;
        if !servers.contains_key(&final_tag) {
            bail!("unknown final DNS server: {final_tag}")
        }
        Ok(Self {
            inner: Arc::new(Inner {
                servers,
                rules: config.rules.clone(),
                final_tag,
                cache: Mutex::new(DnsCache::new(config.cache_capacity.unwrap_or(4096).max(1))),
                flights: Mutex::new(HashMap::new()),
                cache_enabled: !config.disable_cache.unwrap_or(false),
                http: reqwest::Client::builder().timeout(HTTP_TIMEOUT).build()?,
            }),
        })
    }
    pub async fn lookup(&self, domain: &str) -> Result<Vec<IpAddr>> {
        self.lookup_with(domain, None, false).await
    }
    pub async fn lookup_with(
        &self,
        domain: &str,
        server_tag: Option<&str>,
        disable_cache: bool,
    ) -> Result<Vec<IpAddr>> {
        let name = normalize(domain);
        let (a, aaaa) = tokio::join!(
            self.lookup_type(&name, 1, server_tag, disable_cache),
            self.lookup_type(&name, 28, server_tag, disable_cache)
        );
        let mut result = a.unwrap_or_default();
        result.extend(aaaa.unwrap_or_default());
        result.sort();
        result.dedup();
        if result.is_empty() {
            bail!("DNS returned no addresses for {name}")
        }
        Ok(result)
    }
    pub async fn exchange(&self, request: &[u8]) -> Result<Vec<u8>> {
        let (name, qtype, question_end) = parse_question(request)?;
        let request_id = dns_id(request)?;
        let key = CacheKey::Wire(canonical_query(request));
        let value = self
            .cached(key, || async {
                let server = self.select_server(&name)?;
                let response = if server.config.r#type == "local" {
                    local_response(request, &name, qtype, question_end).await?
                } else {
                    server.query(&self.inner.http, request).await?
                };
                validate_response(request_id, &response)?;
                let ttl = if matches!(response[3] & 0x0f, 0 | 3) {
                    Duration::from_secs(response_ttl(&response).clamp(1, 86400) as u64)
                } else {
                    Duration::ZERO
                };
                let mut canonical = response;
                canonical[..2].fill(0);
                Ok((CacheValue::Wire(canonical), ttl))
            })
            .await?;
        match value {
            CacheValue::Wire(mut response) => {
                response[..2].copy_from_slice(&request_id.to_be_bytes());
                Ok(response)
            }
            CacheValue::Addresses(_) => bail!("invalid DNS wire cache entry"),
        }
    }
    async fn lookup_type(
        &self,
        name: &str,
        qtype: u16,
        server_tag: Option<&str>,
        disable_cache: bool,
    ) -> Result<Vec<IpAddr>> {
        let key = CacheKey::Lookup(name.to_owned(), qtype);
        let load = || async {
            let server = match server_tag {
                Some(tag) => self
                    .inner
                    .servers
                    .get(tag)
                    .cloned()
                    .with_context(|| format!("unknown DNS server: {tag}"))?,
                None => self.select_server(name)?.clone(),
            };
            if server.config.r#type == "local" {
                let values = tokio::net::lookup_host((name, 0))
                    .await?
                    .map(|value| value.ip())
                    .filter(|ip| matches!((qtype, ip), (1, IpAddr::V4(_)) | (28, IpAddr::V6(_))))
                    .collect();
                return Ok((CacheValue::Addresses(values), Duration::from_secs(30)));
            }
            let id = rand::rng().random();
            let request = build_query(id, name, qtype)?;
            let response = server.query(&self.inner.http, &request).await?;
            let (addresses, ttl) = parse_response(id, qtype, &response)?;
            Ok((
                CacheValue::Addresses(addresses),
                Duration::from_secs(ttl.clamp(1, 86400) as u64),
            ))
        };
        let value = if disable_cache {
            load().await?.0
        } else {
            self.cached(key, load).await?
        };
        match value {
            CacheValue::Addresses(addresses) => Ok(addresses),
            CacheValue::Wire(_) => bail!("invalid DNS address cache entry"),
        }
    }
    async fn cached<F, Fut>(&self, key: CacheKey, load: F) -> Result<CacheValue>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<(CacheValue, Duration)>>,
    {
        if self.inner.cache_enabled
            && let Some(value) = self
                .inner
                .cache
                .lock()
                .expect("DNS cache lock poisoned")
                .get(&key)
        {
            return Ok(value);
        }
        let (flight, leader) = {
            let mut flights = self.inner.flights.lock().expect("DNS flight lock poisoned");
            if let Some(flight) = flights.get(&key) {
                (flight.clone(), false)
            } else {
                let flight = Arc::new(Flight::new());
                flights.insert(key.clone(), flight.clone());
                (flight, true)
            }
        };
        if !leader {
            return flight.wait().await;
        }
        let result = load().await;
        let shared = match result {
            Ok((value, ttl)) => {
                if self.inner.cache_enabled && !ttl.is_zero() {
                    self.inner
                        .cache
                        .lock()
                        .expect("DNS cache lock poisoned")
                        .insert(key.clone(), value.clone(), ttl);
                }
                Ok(value)
            }
            Err(error) => Err(format!("{error:#}")),
        };
        flight.complete(shared.clone());
        self.inner
            .flights
            .lock()
            .expect("DNS flight lock poisoned")
            .remove(&key);
        shared.map_err(anyhow::Error::msg)
    }
    fn select_server(&self, name: &str) -> Result<&Arc<Upstream>> {
        let tag = self
            .inner
            .rules
            .iter()
            .find(|r| dns_rule_matches(r, name))
            .and_then(|r| r.server.as_ref())
            .unwrap_or(&self.inner.final_tag);
        self.inner
            .servers
            .get(tag)
            .with_context(|| format!("unknown DNS server: {tag}"))
    }
}

impl Flight {
    fn new() -> Self {
        Self {
            result: Mutex::new(None),
            ready: Notify::new(),
        }
    }

    async fn wait(&self) -> Result<CacheValue> {
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

    fn complete(&self, result: std::result::Result<CacheValue, String>) {
        *self.result.lock().expect("DNS flight result lock poisoned") = Some(result);
        self.ready.notify_waiters();
    }
}

impl DnsCache {
    fn new(capacity: usize) -> Self {
        Self {
            entries: HashMap::new(),
            expiry: BinaryHeap::new(),
            lru: VecDeque::new(),
            capacity,
            clock: 0,
        }
    }

    fn get(&mut self, key: &CacheKey) -> Option<CacheValue> {
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

    fn insert(&mut self, key: CacheKey, value: CacheValue, ttl: Duration) {
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

fn parse_question(request: &[u8]) -> Result<(String, u16, usize)> {
    if request.len() < 12 || u16::from_be_bytes([request[4], request[5]]) == 0 {
        bail!("invalid DNS query")
    }
    let mut position = 12;
    let mut labels = Vec::new();
    loop {
        let length = *request.get(position).context("truncated DNS question")? as usize;
        position += 1;
        if length == 0 {
            break;
        }
        if length > 63 {
            bail!("compressed DNS questions are unsupported")
        }
        let label = request
            .get(position..position + length)
            .context("truncated DNS question label")?;
        labels.push(std::str::from_utf8(label)?.to_owned());
        position += length;
    }
    let fields = request
        .get(position..position + 4)
        .context("truncated DNS question fields")?;
    let qtype = u16::from_be_bytes([fields[0], fields[1]]);
    Ok((normalize(&labels.join(".")), qtype, position + 4))
}

async fn local_response(
    request: &[u8],
    name: &str,
    qtype: u16,
    question_end: usize,
) -> Result<Vec<u8>> {
    let addresses: Vec<_> = tokio::net::lookup_host((name, 0))
        .await?
        .map(|address| address.ip())
        .filter(|address| matches!((qtype, address), (1, IpAddr::V4(_)) | (28, IpAddr::V6(_))))
        .collect();
    let mut response = request[..question_end].to_vec();
    response[2] = 0x81;
    response[3] = 0x80;
    response[6..8].copy_from_slice(&(addresses.len() as u16).to_be_bytes());
    response[8..12].fill(0);
    for address in addresses {
        response.extend([0xc0, 0x0c]);
        response.extend(qtype.to_be_bytes());
        response.extend(1u16.to_be_bytes());
        response.extend(30u32.to_be_bytes());
        match address {
            IpAddr::V4(address) => {
                response.extend(4u16.to_be_bytes());
                response.extend(address.octets());
            }
            IpAddr::V6(address) => {
                response.extend(16u16.to_be_bytes());
                response.extend(address.octets());
            }
        }
    }
    Ok(response)
}
fn normalize(s: &str) -> String {
    s.trim_end_matches('.').to_ascii_lowercase()
}
fn dns_rule_matches(r: &DnsRule, name: &str) -> bool {
    let exact = r.domain.is_empty() || r.domain.iter().any(|v| normalize(v) == name);
    let suffix = r.domain_suffix.is_empty()
        || r.domain_suffix.iter().any(|v| {
            let v = normalize(v);
            name == v || name.ends_with(&format!(".{v}"))
        });
    let keyword = r.domain_keyword.is_empty()
        || r.domain_keyword
            .iter()
            .any(|v| name.contains(&v.to_ascii_lowercase()));
    exact && suffix && keyword
}
fn build_query(id: u16, name: &str, qtype: u16) -> Result<Vec<u8>> {
    let mut b = Vec::with_capacity(64);
    b.extend(id.to_be_bytes());
    b.extend([1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 {
            bail!("invalid DNS name")
        };
        b.push(label.len() as u8);
        b.extend(label.as_bytes())
    }
    b.push(0);
    b.extend(qtype.to_be_bytes());
    b.extend(1u16.to_be_bytes());
    Ok(b)
}
impl Upstream {
    fn new(config: DnsServer, dot_tls: Option<TlsConnector>) -> Result<Self> {
        let kind = config.r#type.as_str();
        if !matches!(kind, "" | "udp" | "tcp" | "tls" | "https" | "local") {
            bail!("unsupported DNS server type: {kind}")
        }
        let endpoint = if matches!(kind, "" | "udp" | "tcp" | "tls") {
            let host = config
                .server
                .clone()
                .context("DNS server missing address")?;
            Some(Arc::new(Endpoint {
                host,
                port: config
                    .server_port
                    .unwrap_or(if kind == "tls" { 853 } else { 53 }),
                address: OnceCell::new(),
            }))
        } else {
            None
        };
        let stream = match kind {
            "" | "udp" | "tcp" => Some(TcpPool::new(
                endpoint.clone().expect("stream DNS endpoint"),
                None,
            )),
            "tls" => Some(TcpPool::new(
                endpoint.clone().expect("DoT endpoint"),
                Some(dot_tls.context("DoT TLS configuration unavailable")?),
            )),
            _ => None,
        };
        Ok(Self {
            config,
            endpoint,
            udp: OnceCell::new(),
            stream,
        })
    }

    async fn query(&self, http: &reqwest::Client, request: &[u8]) -> Result<Vec<u8>> {
        match self.config.r#type.as_str() {
            "" | "udp" => {
                let endpoint = self.endpoint.as_ref().expect("UDP endpoint");
                let multiplexer = self
                    .udp
                    .get_or_try_init(|| async {
                        UdpMultiplexer::connect(endpoint.resolve().await?).await
                    })
                    .await?;
                let response = multiplexer.query(request).await?;
                if response.get(2).is_some_and(|flags| flags & 2 != 0) {
                    self.stream
                        .as_ref()
                        .expect("UDP TCP fallback pool")
                        .query(request)
                        .await
                } else {
                    Ok(response)
                }
            }
            "tcp" | "tls" => {
                self.stream
                    .as_ref()
                    .expect("stream DNS pool")
                    .query(request)
                    .await
            }
            "https" => query_https(http, &self.config, request).await,
            "local" => bail!("local DNS query requires parsed question"),
            other => bail!("unsupported DNS server type: {other}"),
        }
    }
}

impl Endpoint {
    async fn resolve(&self) -> Result<SocketAddr> {
        self.address
            .get_or_try_init(|| async {
                tokio::net::lookup_host((self.host.as_str(), self.port))
                    .await?
                    .next()
                    .context("DNS server did not resolve")
            })
            .await
            .copied()
    }
}

impl UdpMultiplexer {
    async fn connect(address: SocketAddr) -> Result<Arc<Self>> {
        let socket = Arc::new(
            UdpSocket::bind(if address.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            })
            .await?,
        );
        socket.connect(address).await?;
        let pending: PendingDatagrams = Arc::new(Mutex::new(HashMap::new()));
        let reader_socket = socket.clone();
        let reader_pending = pending.clone();
        tokio::spawn(async move {
            let mut buffer = vec![0; MAX_DNS_MESSAGE];
            loop {
                let length = match reader_socket.recv(&mut buffer).await {
                    Ok(length) => length,
                    Err(error) => {
                        let senders = {
                            let mut pending = reader_pending
                                .lock()
                                .expect("DNS UDP pending lock poisoned");
                            pending
                                .drain()
                                .map(|(_, sender)| sender)
                                .collect::<Vec<_>>()
                        };
                        let message = format!("DNS UDP receive failed: {error}");
                        for sender in senders {
                            let _ = sender.send(Err(message.clone()));
                        }
                        break;
                    }
                };
                let Some(id_bytes) = buffer.get(..2) else {
                    continue;
                };
                let id = u16::from_be_bytes([id_bytes[0], id_bytes[1]]);
                let sender = reader_pending
                    .lock()
                    .expect("DNS UDP pending lock poisoned")
                    .remove(&id);
                if let Some(sender) = sender {
                    let _ = sender.send(Ok(buffer[..length].to_vec()));
                }
            }
        });
        Ok(Arc::new(Self {
            socket,
            pending,
            next_id: AtomicU32::new(rand::rng().random()),
        }))
    }

    async fn query(&self, request: &[u8]) -> Result<Vec<u8>> {
        let original_id = dns_id(request)?;
        let (internal_id, receiver) = {
            let mut pending = self.pending.lock().expect("DNS UDP pending lock poisoned");
            let mut selected = None;
            for _ in 0..=u16::MAX {
                let candidate = self.next_id.fetch_add(1, Ordering::Relaxed) as u16;
                if let std::collections::hash_map::Entry::Vacant(entry) = pending.entry(candidate) {
                    let (sender, receiver) = oneshot::channel();
                    entry.insert(sender);
                    selected = Some((candidate, receiver));
                    break;
                }
            }
            selected.context("DNS UDP transaction ID space exhausted")?
        };
        let mut wire = request.to_vec();
        wire[..2].copy_from_slice(&internal_id.to_be_bytes());
        if let Err(error) = self.socket.send(&wire).await {
            self.pending
                .lock()
                .expect("DNS UDP pending lock poisoned")
                .remove(&internal_id);
            return Err(error.into());
        }
        let received = match timeout(DNS_TIMEOUT, receiver).await {
            Ok(Ok(result)) => result.map_err(anyhow::Error::msg)?,
            Ok(Err(_)) => bail!("DNS UDP response dispatcher stopped"),
            Err(_) => {
                self.pending
                    .lock()
                    .expect("DNS UDP pending lock poisoned")
                    .remove(&internal_id);
                bail!("DNS timeout")
            }
        };
        let mut response = received;
        response
            .get_mut(..2)
            .context("truncated DNS UDP response")?
            .copy_from_slice(&original_id.to_be_bytes());
        Ok(response)
    }
}

impl TcpPool {
    fn new(endpoint: Arc<Endpoint>, tls: Option<TlsConnector>) -> Self {
        Self {
            endpoint,
            tls,
            idle: Mutex::new(Vec::new()),
            permits: Arc::new(Semaphore::new(STREAM_POOL_SIZE)),
        }
    }

    async fn query(&self, request: &[u8]) -> Result<Vec<u8>> {
        let _permit = self
            .permits
            .acquire()
            .await
            .context("DNS stream pool closed")?;
        let mut last_error = None;
        for _ in 0..2 {
            let mut stream = match self.take_idle() {
                Some(stream) => stream,
                None => self.connect().await?,
            };
            match exchange_stream(&mut *stream, request).await {
                Ok(response) => {
                    let mut idle = self.idle.lock().expect("DNS stream pool lock poisoned");
                    if idle.len() < STREAM_POOL_SIZE {
                        idle.push(IdleConnection {
                            stream,
                            last_used: Instant::now(),
                        });
                    }
                    return Ok(response);
                }
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.context("DNS stream query failed")?)
    }

    fn take_idle(&self) -> Option<Box<dyn DnsIo>> {
        let now = Instant::now();
        let mut idle = self.idle.lock().expect("DNS stream pool lock poisoned");
        while let Some(connection) = idle.pop() {
            if now.saturating_duration_since(connection.last_used) < STREAM_IDLE_TIMEOUT {
                return Some(connection.stream);
            }
        }
        None
    }

    async fn connect(&self) -> Result<Box<dyn DnsIo>> {
        let address = self.endpoint.resolve().await?;
        let tcp = timeout(DNS_TIMEOUT, TcpStream::connect(address))
            .await
            .context("DNS connect timeout")??;
        if let Some(connector) = &self.tls {
            let name = rustls::pki_types::ServerName::try_from(self.endpoint.host.clone())
                .context("invalid DoT server name")?;
            Ok(Box::new(connector.connect(name, tcp).await?))
        } else {
            Ok(Box::new(tcp))
        }
    }
}

async fn exchange_stream(stream: &mut dyn DnsIo, q: &[u8]) -> Result<Vec<u8>> {
    stream
        .write_u16(q.len().try_into().context("DNS query too large")?)
        .await?;
    stream.write_all(q).await?;
    stream.flush().await?;
    let n = stream.read_u16().await? as usize;
    let mut response = vec![0; n];
    stream.read_exact(&mut response).await?;
    Ok(response)
}

trait DnsIo: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> DnsIo for T {}
async fn query_https(http: &reqwest::Client, s: &DnsServer, q: &[u8]) -> Result<Vec<u8>> {
    let host = s
        .server
        .as_deref()
        .context("HTTPS DNS server missing address")?;
    let path = s.path.as_deref().unwrap_or("/dns-query");
    let url = if host.starts_with("http://") || host.starts_with("https://") {
        format!("{}{}", host.trim_end_matches('/'), path)
    } else {
        format!("https://{host}:{}{path}", s.server_port.unwrap_or(443))
    };
    let r = http
        .post(url)
        .header("content-type", "application/dns-message")
        .header("accept", "application/dns-message")
        .body(q.to_vec())
        .send()
        .await?
        .error_for_status()?;
    Ok(r.bytes().await?.to_vec())
}

fn dns_id(message: &[u8]) -> Result<u16> {
    let bytes = message.get(..2).context("truncated DNS message")?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn canonical_query(request: &[u8]) -> Vec<u8> {
    let mut key = request.to_vec();
    if key.len() >= 2 {
        key[..2].fill(0);
    }
    key
}

fn validate_response(expected_id: u16, response: &[u8]) -> Result<()> {
    if response.len() < 12 {
        bail!("truncated DNS response")
    }
    if dns_id(response)? != expected_id {
        bail!("DNS response transaction ID mismatch")
    }
    if response[2] & 0x80 == 0 {
        bail!("DNS message is not a response")
    }
    Ok(())
}

fn response_ttl(response: &[u8]) -> u32 {
    ttl_offsets(response)
        .ok()
        .and_then(|offsets| {
            offsets
                .into_iter()
                .filter(|(_, record_type, _)| *record_type != 41)
                .map(|(_, _, ttl)| ttl)
                .min()
        })
        .unwrap_or(30)
}

fn age_response_ttls(response: &mut [u8], elapsed: u32) {
    let Ok(offsets) = ttl_offsets(response) else {
        return;
    };
    for (offset, record_type, ttl) in offsets {
        if record_type != 41 {
            response[offset..offset + 4]
                .copy_from_slice(&ttl.saturating_sub(elapsed).to_be_bytes());
        }
    }
}

fn ttl_offsets(message: &[u8]) -> Result<Vec<(usize, u16, u32)>> {
    if message.len() < 12 {
        bail!("truncated DNS message")
    }
    let questions = u16::from_be_bytes([message[4], message[5]]) as usize;
    let records = u16::from_be_bytes([message[6], message[7]]) as usize
        + u16::from_be_bytes([message[8], message[9]]) as usize
        + u16::from_be_bytes([message[10], message[11]]) as usize;
    let mut position = 12;
    for _ in 0..questions {
        skip_name(message, &mut position)?;
        position = position
            .checked_add(4)
            .filter(|value| *value <= message.len())
            .context("truncated DNS question")?;
    }
    let mut offsets = Vec::with_capacity(records);
    for _ in 0..records {
        skip_name(message, &mut position)?;
        let header = message
            .get(position..position + 10)
            .context("truncated DNS record")?;
        let record_type = u16::from_be_bytes([header[0], header[1]]);
        let ttl = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);
        let length = u16::from_be_bytes([header[8], header[9]]) as usize;
        offsets.push((position + 4, record_type, ttl));
        position = position
            .checked_add(10 + length)
            .filter(|value| *value <= message.len())
            .context("truncated DNS record data")?;
    }
    Ok(offsets)
}

fn parse_response(id: u16, qtype: u16, b: &[u8]) -> Result<(Vec<IpAddr>, u32)> {
    if b.len() < 12 || u16::from_be_bytes([b[0], b[1]]) != id {
        bail!("invalid DNS response")
    };
    let flags = u16::from_be_bytes([b[2], b[3]]);
    if flags & 0x8000 == 0 || flags & 15 != 0 {
        bail!("DNS error rcode {}", flags & 15)
    }
    let qd = u16::from_be_bytes([b[4], b[5]]) as usize;
    let an = u16::from_be_bytes([b[6], b[7]]) as usize;
    let mut p = 12;
    for _ in 0..qd {
        skip_name(b, &mut p)?;
        p = p
            .checked_add(4)
            .filter(|v| *v <= b.len())
            .context("truncated DNS question")?
    }
    let mut out = Vec::new();
    let mut ttl = u32::MAX;
    for _ in 0..an {
        skip_name(b, &mut p)?;
        if p + 10 > b.len() {
            bail!("truncated DNS answer")
        };
        let typ = u16::from_be_bytes([b[p], b[p + 1]]);
        let record_ttl = u32::from_be_bytes([b[p + 4], b[p + 5], b[p + 6], b[p + 7]]);
        let len = u16::from_be_bytes([b[p + 8], b[p + 9]]) as usize;
        p += 10;
        if p + len > b.len() {
            bail!("truncated DNS rdata")
        };
        if typ == qtype {
            match (typ, len) {
                (1, 4) => out.push(IpAddr::from([b[p], b[p + 1], b[p + 2], b[p + 3]])),
                (28, 16) => {
                    let mut a = [0; 16];
                    a.copy_from_slice(&b[p..p + 16]);
                    out.push(IpAddr::from(a))
                }
                _ => {}
            }
            ttl = ttl.min(record_ttl)
        }
        p += len
    }
    Ok((out, if ttl == u32::MAX { 30 } else { ttl }))
}

#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub fn fuzz_dns_message(input: &[u8]) {
    let id = input
        .get(..2)
        .map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]))
        .unwrap_or(0);
    for qtype in [1, 28] {
        let _ = parse_response(id, qtype, input);
    }
}
fn skip_name(b: &[u8], p: &mut usize) -> Result<()> {
    let mut count = 0;
    loop {
        if *p >= b.len() {
            bail!("truncated DNS name")
        };
        let n = b[*p];
        *p += 1;
        if n == 0 {
            return Ok(());
        }
        if n & 0xc0 == 0xc0 {
            if *p >= b.len() {
                bail!("truncated DNS pointer")
            };
            *p += 1;
            return Ok(());
        }
        if n & 0xc0 != 0 || n > 63 {
            bail!("invalid DNS label")
        };
        *p += n as usize;
        if *p > b.len() {
            bail!("truncated DNS label")
        };
        count += 1;
        if count > 127 {
            bail!("invalid DNS name")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    fn test_server(kind: &str, address: SocketAddr) -> DnsConfig {
        DnsConfig {
            servers: vec![DnsServer {
                r#type: kind.into(),
                tag: "test".into(),
                server: Some(address.ip().to_string()),
                server_port: Some(address.port()),
                path: None,
            }],
            final_server: Some("test".into()),
            ..Default::default()
        }
    }

    fn answer_query(query: &[u8]) -> Vec<u8> {
        let qtype = u16::from_be_bytes([query[query.len() - 4], query[query.len() - 3]]);
        let mut response = query.to_vec();
        response[2] = 0x81;
        response[3] = 0x80;
        response[6] = 0;
        response[7] = 1;
        response.extend([0xc0, 0x0c]);
        response.extend(qtype.to_be_bytes());
        response.extend(1u16.to_be_bytes());
        response.extend(60u32.to_be_bytes());
        if qtype == 1 {
            response.extend(4u16.to_be_bytes());
            response.extend([1, 2, 3, 4])
        } else {
            response.extend(16u16.to_be_bytes());
            response.extend([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
        }
        response
    }

    #[test]
    fn query_encoding() {
        let q = build_query(7, "example.com", 1).unwrap();
        assert_eq!(&q[12..25], b"\x07example\x03com\0");
    }
    #[test]
    fn rule_suffix() {
        let r = DnsRule {
            domain_suffix: vec!["example.com".into()],
            ..Default::default()
        };
        assert!(dns_rule_matches(&r, "www.example.com"));
        assert!(!dns_rule_matches(&r, "badexample.com"));
    }
    #[tokio::test]
    async fn udp_lookup_and_ttl_cache() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed = requests.clone();
        tokio::spawn(async move {
            let mut buffer = [0; 512];
            for _ in 0..2 {
                let (n, peer) = socket.recv_from(&mut buffer).await.unwrap();
                observed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let response = answer_query(&buffer[..n]);
                socket.send_to(&response, peer).await.unwrap();
            }
        });
        let config = test_server("udp", address);
        let resolver = DnsResolver::new(&config).unwrap();
        let first = resolver.lookup("example.test").await.unwrap();
        assert!(first.contains(&"1.2.3.4".parse().unwrap()));
        let second = resolver.lookup("example.test").await.unwrap();
        assert_eq!(first, second);
        assert_eq!(requests.load(std::sync::atomic::Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn raw_exchange_preserves_dns_message() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let requests = Arc::new(AtomicUsize::new(0));
        let observed = requests.clone();
        tokio::spawn(async move {
            let mut buffer = [0; 512];
            let (length, peer) = socket.recv_from(&mut buffer).await.unwrap();
            observed.fetch_add(1, Ordering::Relaxed);
            let mut response = buffer[..length].to_vec();
            response[2] = 0x81;
            response[3] = 0x80;
            socket.send_to(&response, peer).await.unwrap();
        });
        let resolver = DnsResolver::new(&test_server("udp", address)).unwrap();
        let query = build_query(42, "raw.example", 16).unwrap();
        let response = resolver.exchange(&query).await.unwrap();
        assert_eq!(&response[..2], &42u16.to_be_bytes());
        assert_eq!(response[2] & 0x80, 0x80);
        assert_eq!(&response[12..], &query[12..]);
        let second_query = build_query(43, "raw.example", 16).unwrap();
        let second = resolver.exchange(&second_query).await.unwrap();
        assert_eq!(&second[..2], &43u16.to_be_bytes());
        assert_eq!(requests.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn singleflight_coalesces_concurrent_lookups() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let requests = Arc::new(AtomicUsize::new(0));
        let observed = requests.clone();
        tokio::spawn(async move {
            let mut buffer = [0; 512];
            for _ in 0..2 {
                let (length, peer) = socket.recv_from(&mut buffer).await.unwrap();
                observed.fetch_add(1, Ordering::Relaxed);
                tokio::time::sleep(Duration::from_millis(25)).await;
                socket
                    .send_to(&answer_query(&buffer[..length]), peer)
                    .await
                    .unwrap();
            }
        });
        let resolver = DnsResolver::new(&test_server("udp", address)).unwrap();
        let mut tasks = Vec::new();
        for _ in 0..32 {
            let resolver = resolver.clone();
            tasks.push(tokio::spawn(async move {
                resolver.lookup("singleflight.example").await.unwrap()
            }));
        }
        for task in tasks {
            assert!(task.await.unwrap().contains(&"1.2.3.4".parse().unwrap()));
        }
        assert_eq!(requests.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn udp_socket_reuse_dispatches_out_of_order_responses() {
        const REQUESTS: usize = 64;
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let peers = Arc::new(Mutex::new(Vec::new()));
        let observed_peers = peers.clone();
        tokio::spawn(async move {
            let mut received = Vec::new();
            let mut buffer = [0; 512];
            for _ in 0..REQUESTS {
                let (length, peer) = socket.recv_from(&mut buffer).await.unwrap();
                observed_peers
                    .lock()
                    .expect("peer lock poisoned")
                    .push(peer);
                received.push((buffer[..length].to_vec(), peer));
            }
            for (query, peer) in received.into_iter().rev() {
                let mut response = query;
                response[2] = 0x81;
                response[3] = 0x80;
                socket.send_to(&response, peer).await.unwrap();
            }
        });
        let mut config = test_server("udp", address);
        config.disable_cache = Some(true);
        let resolver = DnsResolver::new(&config).unwrap();
        let mut tasks = Vec::new();
        for index in 0..REQUESTS {
            let resolver = resolver.clone();
            tasks.push(tokio::spawn(async move {
                let query = build_query(index as u16, &format!("q{index}.example"), 16).unwrap();
                resolver.exchange(&query).await.unwrap()
            }));
        }
        for (index, task) in tasks.into_iter().enumerate() {
            let response = task.await.unwrap();
            assert_eq!(dns_id(&response).unwrap(), index as u16);
        }
        let peers = peers.lock().expect("peer lock poisoned");
        assert_eq!(peers.len(), REQUESTS);
        assert!(peers.iter().all(|peer| *peer == peers[0]));
    }

    #[tokio::test]
    async fn tcp_pool_reuses_connections_and_recovers_from_close() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let accepts = Arc::new(AtomicUsize::new(0));
        let observed = accepts.clone();
        tokio::spawn(async move {
            for connection_index in 0..2 {
                let (mut stream, _) = listener.accept().await.unwrap();
                observed.fetch_add(1, Ordering::Relaxed);
                let requests_on_connection = if connection_index == 0 { 2 } else { 1 };
                for _ in 0..requests_on_connection {
                    let length = stream.read_u16().await.unwrap() as usize;
                    let mut query = vec![0; length];
                    stream.read_exact(&mut query).await.unwrap();
                    let mut response = query;
                    response[2] = 0x81;
                    response[3] = 0x80;
                    stream.write_u16(response.len() as u16).await.unwrap();
                    stream.write_all(&response).await.unwrap();
                }
            }
        });
        let mut config = test_server("tcp", address);
        config.disable_cache = Some(true);
        let resolver = DnsResolver::new(&config).unwrap();
        for index in 0..2 {
            let query = build_query(index, &format!("reuse{index}.example"), 16).unwrap();
            resolver.exchange(&query).await.unwrap();
        }
        assert_eq!(accepts.load(Ordering::Relaxed), 1);

        let third = build_query(3, "reconnect.example", 16).unwrap();
        resolver.exchange(&third).await.unwrap();
        assert_eq!(accepts.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn lru_capacity_evicts_the_least_recent_entry() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let requests = Arc::new(AtomicUsize::new(0));
        let observed = requests.clone();
        tokio::spawn(async move {
            let mut buffer = [0; 512];
            for _ in 0..3 {
                let (length, peer) = socket.recv_from(&mut buffer).await.unwrap();
                observed.fetch_add(1, Ordering::Relaxed);
                let mut response = buffer[..length].to_vec();
                response[2] = 0x81;
                response[3] = 0x80;
                socket.send_to(&response, peer).await.unwrap();
            }
        });
        let mut config = test_server("udp", address);
        config.cache_capacity = Some(1);
        let resolver = DnsResolver::new(&config).unwrap();
        for (id, name) in [(1, "a.example"), (2, "b.example"), (3, "a.example")] {
            resolver
                .exchange(&build_query(id, name, 16).unwrap())
                .await
                .unwrap();
        }
        assert_eq!(requests.load(Ordering::Relaxed), 3);
    }
}

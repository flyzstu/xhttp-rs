mod cache;
mod message;
mod transport;

use anyhow::{Context, Result, bail};
use rand::Rng;
use std::{
    collections::HashMap,
    future::Future,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio_rustls::TlsConnector;

use crate::singbox::{DnsConfig, DnsRule};
use crate::util::parse_duration;

use self::cache::{CacheKey, CacheValue, DnsCache, Flight};
use self::message::{
    add_client_subnet, build_query, build_query_with_subnet, canonical_query, dns_id,
    dns_rule_matches, local_response, normalize, optimistic_enabled, parse_client_subnet,
    parse_https_ech, parse_question, parse_response, refused_response, response_ttl,
    rewrite_response_ttls, validate_dns_rule, validate_response, validate_strategy,
};
use self::transport::Upstream;

#[cfg(feature = "fuzzing")]
pub use self::message::fuzz_dns_message;

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
    strategy: Option<String>,
    timeout: Duration,
    client_subnet: Option<String>,
    http: reqwest::Client,
}

#[derive(Debug, Clone, Default)]
pub struct LookupOptions<'a> {
    pub server: Option<&'a str>,
    pub disable_cache: bool,
    pub rewrite_ttl: Option<u32>,
    pub timeout: Option<Duration>,
    pub strategy: Option<&'a str>,
    pub client_subnet: Option<&'a str>,
}

impl DnsResolver {
    pub fn new(config: &DnsConfig) -> Result<Self> {
        crate::install_crypto_provider();
        validate_strategy(config.strategy.as_deref())?;
        if let Some(subnet) = &config.client_subnet {
            parse_client_subnet(subnet)?;
        }
        if config.reverse_mapping {
            bail!("DNS reverse_mapping requires a TUN-style inbound and is not supported")
        }
        if config.optimistic.as_ref().is_some_and(optimistic_enabled) {
            bail!("optimistic DNS cache is not supported")
        }
        for rule in &config.rules {
            validate_dns_rule(rule, true)?;
        }
        let dns_timeout = config
            .timeout
            .as_deref()
            .map(parse_duration)
            .transpose()?
            .unwrap_or(DNS_TIMEOUT);
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
                cache: Mutex::new(DnsCache::new(
                    config.cache_capacity.unwrap_or(4096).max(1),
                    config.disable_expire.unwrap_or(false),
                )),
                flights: Mutex::new(HashMap::new()),
                cache_enabled: !config.disable_cache.unwrap_or(false),
                strategy: config.strategy.clone(),
                timeout: dns_timeout,
                client_subnet: config.client_subnet.clone(),
                http: reqwest::Client::builder()
                    .timeout(
                        config
                            .timeout
                            .as_ref()
                            .map_or(HTTP_TIMEOUT, |_| dns_timeout),
                    )
                    .build()?,
            }),
        })
    }
    pub async fn lookup(&self, domain: &str) -> Result<Vec<IpAddr>> {
        self.lookup_with_options(domain, &LookupOptions::default())
            .await
    }
    pub async fn lookup_with(
        &self,
        domain: &str,
        server_tag: Option<&str>,
        disable_cache: bool,
    ) -> Result<Vec<IpAddr>> {
        self.lookup_with_options(
            domain,
            &LookupOptions {
                server: server_tag,
                disable_cache,
                ..Default::default()
            },
        )
        .await
    }

    pub async fn lookup_with_options(
        &self,
        domain: &str,
        options: &LookupOptions<'_>,
    ) -> Result<Vec<IpAddr>> {
        let name = normalize(domain);
        let strategy = options
            .strategy
            .or_else(|| {
                self.select_rule(&name, 1)
                    .or_else(|| self.select_rule(&name, 28))
                    .and_then(|rule| rule.strategy.as_deref())
            })
            .or(self.inner.strategy.as_deref());
        validate_strategy(strategy)?;
        let query = |qtype| self.lookup_type(&name, qtype, options);
        let (a, aaaa) = match strategy {
            Some("ipv4_only") => (query(1).await, Ok(Vec::new())),
            Some("ipv6_only") => (Ok(Vec::new()), query(28).await),
            _ => tokio::join!(query(1), query(28)),
        };
        let mut result = a.unwrap_or_default();
        result.extend(aaaa.unwrap_or_default());
        result.sort();
        result.dedup();
        match strategy {
            Some("prefer_ipv4") => result.sort_by_key(|address| !address.is_ipv4()),
            Some("prefer_ipv6") => result.sort_by_key(IpAddr::is_ipv4),
            _ => {}
        }
        if result.is_empty() {
            bail!("DNS returned no addresses for {name}")
        }
        Ok(result)
    }
    pub async fn exchange(&self, request: &[u8]) -> Result<Vec<u8>> {
        let (name, qtype, question_end) = parse_question(request)?;
        let request_id = dns_id(request)?;
        let rule = self.select_rule(&name, qtype);
        if rule.is_some_and(|rule| rule.action.as_deref() == Some("reject")) {
            if rule.and_then(|rule| rule.method.as_deref()) == Some("drop") {
                bail!("DNS query dropped by rule")
            }
            return refused_response(request, question_end);
        }
        let server_tag = rule
            .and_then(|rule| rule.server.as_deref())
            .unwrap_or(&self.inner.final_tag);
        let server = self
            .inner
            .servers
            .get(server_tag)
            .cloned()
            .with_context(|| format!("unknown DNS server: {server_tag}"))?;
        let client_subnet = rule
            .and_then(|rule| rule.client_subnet.as_deref())
            .or(self.inner.client_subnet.as_deref());
        let wire = if let Some(subnet) = client_subnet {
            add_client_subnet(request, subnet)?
        } else {
            request.to_vec()
        };
        let key = CacheKey::Wire {
            query: canonical_query(&wire).into(),
            server: server_tag.into(),
        };
        let load = || async {
            let mut response = if server.config.r#type == "local" {
                local_response(&wire, &name, qtype, question_end).await?
            } else {
                tokio::time::timeout(
                    rule.and_then(|rule| rule.timeout.as_deref())
                        .map(parse_duration)
                        .transpose()?
                        .unwrap_or(self.inner.timeout),
                    server.query(&self.inner.http, &wire),
                )
                .await
                .context("DNS query timeout")??
            };
            validate_response(request_id, &response)?;
            if let Some(ttl) = rule.and_then(|rule| rule.rewrite_ttl) {
                rewrite_response_ttls(&mut response, ttl);
            }
            let ttl = if matches!(response[3] & 0x0f, 0 | 3) {
                Duration::from_secs(response_ttl(&response).clamp(1, 86400) as u64)
            } else {
                Duration::ZERO
            };
            let mut canonical = response;
            canonical[..2].fill(0);
            Ok((CacheValue::Wire(canonical), ttl))
        };
        let value = if rule.is_some_and(|rule| rule.disable_cache) {
            load().await?.0
        } else {
            self.cached(key, load).await?
        };
        match value {
            CacheValue::Wire(mut response) => {
                response[..2].copy_from_slice(&request_id.to_be_bytes());
                Ok(response)
            }
            CacheValue::Addresses(_) => bail!("invalid DNS wire cache entry"),
        }
    }

    pub async fn ech_config(&self, domain: &str) -> Result<Vec<u8>> {
        let id = rand::random();
        let query = build_query(id, &normalize(domain), 65)?;
        let response = self.exchange(&query).await?;
        parse_https_ech(id, &response)
    }

    async fn lookup_type(
        &self,
        name: &str,
        qtype: u16,
        options: &LookupOptions<'_>,
    ) -> Result<Vec<IpAddr>> {
        let rule = if options.server.is_none() {
            self.select_rule(name, qtype)
        } else {
            None
        };
        if rule.is_some_and(|rule| rule.action.as_deref() == Some("reject")) {
            bail!("DNS lookup rejected by rule")
        }
        let server_tag = options
            .server
            .or_else(|| rule.and_then(|rule| rule.server.as_deref()));
        let client_subnet = options
            .client_subnet
            .map(str::to_owned)
            .or_else(|| {
                rule.and_then(|rule| rule.client_subnet.as_deref())
                    .map(str::to_owned)
            })
            .or_else(|| self.inner.client_subnet.clone());
        if let Some(subnet) = &client_subnet {
            parse_client_subnet(subnet)?;
        }
        let query_timeout = options
            .timeout
            .or(rule
                .and_then(|rule| rule.timeout.as_deref())
                .map(parse_duration)
                .transpose()?)
            .unwrap_or(self.inner.timeout);
        let rewrite_ttl = options
            .rewrite_ttl
            .or_else(|| rule.and_then(|rule| rule.rewrite_ttl));
        let disable_cache = options.disable_cache || rule.is_some_and(|rule| rule.disable_cache);
        let key = CacheKey::Lookup {
            name: name.into(),
            qtype,
            server: server_tag.map(Into::into),
            client_subnet: client_subnet.as_deref().map(Into::into),
        };
        let load = || async {
            let server = match server_tag {
                Some(tag) => self
                    .inner
                    .servers
                    .get(tag)
                    .cloned()
                    .with_context(|| format!("unknown DNS server: {tag}"))?,
                None => self.select_server(name, qtype)?.clone(),
            };
            if server.config.r#type == "local" {
                let values = tokio::net::lookup_host((name, 0))
                    .await?
                    .map(|value| value.ip())
                    .filter(|ip| matches!((qtype, ip), (1, IpAddr::V4(_)) | (28, IpAddr::V6(_))))
                    .collect();
                return Ok((
                    CacheValue::Addresses(values),
                    Duration::from_secs(rewrite_ttl.unwrap_or(30).clamp(1, 86400) as u64),
                ));
            }
            let id = rand::rng().random();
            let request = build_query_with_subnet(id, name, qtype, client_subnet.as_deref())?;
            let response =
                tokio::time::timeout(query_timeout, server.query(&self.inner.http, &request))
                    .await
                    .context("DNS query timeout")??;
            let (addresses, ttl) = parse_response(id, qtype, &response)?;
            Ok((
                CacheValue::Addresses(addresses),
                Duration::from_secs(rewrite_ttl.unwrap_or(ttl).clamp(1, 86400) as u64),
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
    fn select_rule(&self, name: &str, qtype: u16) -> Option<&DnsRule> {
        self.inner
            .rules
            .iter()
            .find(|rule| dns_rule_matches(rule, name, qtype))
    }

    fn select_server(&self, name: &str, qtype: u16) -> Result<&Arc<Upstream>> {
        let tag = self
            .select_rule(name, qtype)
            .and_then(|rule| rule.server.as_ref())
            .unwrap_or(&self.inner.final_tag);
        self.inner
            .servers
            .get(tag)
            .with_context(|| format!("unknown DNS server: {tag}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UdpSocket;

    use crate::singbox::DnsServer;

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
    fn query_encodes_edns_client_subnet() {
        let query = build_query_with_subnet(7, "example.com", 1, Some("192.0.2.129/24")).unwrap();
        assert_eq!(&query[10..12], &1u16.to_be_bytes());
        assert!(query.ends_with(&[
            0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 11, 0, 8, 0, 7, 0, 1, 24, 0, 192, 0, 2,
        ]));
    }

    #[test]
    fn dns_rules_match_query_type_regex_and_invert() {
        let rule = DnsRule {
            query_type: vec![serde_json::Value::String("HTTPS".into())],
            domain_regex: vec![r"^api\d+\.example$".into()],
            ..Default::default()
        };
        assert!(dns_rule_matches(&rule, "api12.example", 65));
        assert!(!dns_rule_matches(&rule, "api12.example", 1));
        assert!(!dns_rule_matches(&rule, "www.example", 65));
        assert!(dns_rule_matches(
            &DnsRule {
                invert: true,
                ..rule
            },
            "www.example",
            65
        ));
    }

    #[test]
    fn refused_response_preserves_question() {
        let query = build_query(7, "example.com", 1).unwrap();
        let (_, _, question_end) = parse_question(&query).unwrap();
        let response = refused_response(&query, question_end).unwrap();
        assert_eq!(&response[..2], &7u16.to_be_bytes());
        assert_ne!(response[2] & 0x80, 0);
        assert_eq!(response[3] & 0x0f, 5);
        assert_eq!(&response[12..], &query[12..question_end]);
    }

    #[test]
    fn lookup_cache_key_separates_server_and_subnet() {
        let first = CacheKey::Lookup {
            name: "example.com".into(),
            qtype: 1,
            server: Some("a".into()),
            client_subnet: Some("192.0.2.0/24".into()),
        };
        let second = CacheKey::Lookup {
            name: "example.com".into(),
            qtype: 1,
            server: Some("b".into()),
            client_subnet: Some("192.0.2.0/24".into()),
        };
        assert_ne!(first, second);
    }

    #[test]
    fn parses_ech_from_https_record() {
        let query = build_query(7, "example.com", 65).unwrap();
        let mut response = query;
        response[2] = 0x81;
        response[3] = 0x80;
        response[6..8].copy_from_slice(&1u16.to_be_bytes());
        response.extend([0xc0, 0x0c]);
        response.extend(65u16.to_be_bytes());
        response.extend(1u16.to_be_bytes());
        response.extend(60u32.to_be_bytes());
        let ech = [0, 4, 0xfe, 0x0d, 0, 0];
        let mut rdata = Vec::new();
        rdata.extend(1u16.to_be_bytes());
        rdata.push(0);
        rdata.extend(5u16.to_be_bytes());
        rdata.extend((ech.len() as u16).to_be_bytes());
        rdata.extend(ech);
        response.extend((rdata.len() as u16).to_be_bytes());
        response.extend(rdata);
        assert_eq!(parse_https_ech(7, &response).unwrap(), ech);
    }
    #[test]
    fn rule_suffix() {
        let r = DnsRule {
            domain_suffix: vec!["example.com".into()],
            ..Default::default()
        };
        assert!(dns_rule_matches(&r, "www.example.com", 1));
        assert!(!dns_rule_matches(&r, "badexample.com", 1));
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

mod cache;
mod message;
pub(crate) mod transport;

use anyhow::{Context, Result, bail};
use rand::Rng;
use std::{
    collections::HashMap,
    future::Future,
    net::IpAddr,
    sync::{Arc, Mutex, RwLock},
    time::Duration,
};
use tokio_rustls::TlsConnector;

use crate::routing::CompiledRuleSetMap;
use crate::singbox::DnsConfig;
use crate::util::parse_duration;

use self::cache::{CacheKey, CacheValue, DnsCache, Flight};
use self::message::{
    add_client_subnet, build_query, build_query_with_subnet, canonical_query, dns_id,
    dns_rule_matches, local_response, normalize, optimistic_enabled, parse_client_subnet,
    parse_https_ech, parse_question, parse_response, predefined_response, refused_response,
    response_ttl, rewrite_response_ttls, validate_dns_rule, validate_response,
    validate_strategy,
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
    rules: Vec<self::message::CompiledDnsRule>,
    final_tag: String,
    cache: Mutex<DnsCache>,
    flights: Mutex<HashMap<CacheKey, Arc<Flight>>>,
    cache_enabled: bool,
    strategy: Option<String>,
    timeout: Duration,
    client_subnet: Option<String>,
    http: reqwest::Client,
    rule_sets: Option<Arc<RwLock<CompiledRuleSetMap>>>,
    detour: std::sync::RwLock<Option<Arc<dyn transport::DnsUdpDetour>>>,
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
        Self::with_rule_sets(config, None)
    }

    pub(crate) fn with_rule_sets(
        config: &DnsConfig,
        rule_sets: Option<Arc<RwLock<CompiledRuleSetMap>>>,
    ) -> Result<Self> {
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
                rules: config
                    .rules
                    .iter()
                    .map(self::message::CompiledDnsRule::compile)
                    .collect::<Result<Vec<_>>>()?,
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
                rule_sets,
                detour: std::sync::RwLock::new(None),
            }),
        })
    }

    /// Install the outbound provider used for `detour` DNS servers. Called
    /// once the proxy runtime has built its dialers.
    pub(crate) fn set_detour(&self, detour: Arc<dyn transport::DnsUdpDetour>) {
        for server in self.inner.servers.values() {
            server.set_detour(detour.clone());
        }
        *self
            .inner
            .detour
            .write()
            .expect("DNS detour lock poisoned") = Some(detour);
    }

    /// Load persisted DNS cache entries from the `cache_file` path, and
    /// spawn a periodic saver that writes back every 60 seconds.
    pub(crate) fn start_persistence(&self, path: &std::path::Path) {
        match std::fs::read(path) {
            Ok(bytes) => match serde_json::from_slice::<cache::PersistentCache>(&bytes) {
                Ok(snapshot) => {
                    self.inner
                        .cache
                        .lock()
                        .expect("DNS cache lock poisoned")
                        .restore(snapshot);
                    tracing::info!("restored DNS cache from {}", path.display());
                }
                Err(error) => tracing::warn!(
                    %error,
                    "discarding unreadable persisted DNS cache at {}",
                    path.display()
                ),
            },
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => tracing::warn!(
                %error,
                "failed to read persisted DNS cache at {}",
                path.display()
            ),
        }
        let resolver = self.clone();
        let path = path.to_owned();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                resolver.save_cache(&path);
            }
        });
    }

    fn save_cache(&self, path: &std::path::Path) {
        let snapshot = self
            .inner
            .cache
            .lock()
            .expect("DNS cache lock poisoned")
            .snapshot();
        let Ok(bytes) = serde_json::to_vec(&snapshot) else {
            return;
        };
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        if let Err(error) = std::fs::write(path, bytes) {
            tracing::warn!(%error, "failed to persist DNS cache");
        }
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
                    .and_then(|rule| rule.raw.strategy.as_deref())
            })
            .or(self.inner.strategy.as_deref());
        validate_strategy(strategy)?;
        let query = |qtype| self.lookup_type(&name, qtype, options);
        let (a, aaaa) = match strategy {
            Some("ipv4_only") => (query(1).await, Ok(Vec::new())),
            Some("ipv6_only") => (Ok(Vec::new()), query(28).await),
            _ => tokio::join!(query(1), query(28)),
        };
        let mut result = match (a, aaaa) {
            (Ok(a), Ok(aaaa)) => {
                let mut result = a;
                result.extend(aaaa);
                result
            }
            (Ok(a), Err(error)) => {
                tracing::debug!(%error, %name, "DNS AAAA lookup failed, using A");
                a
            }
            (Err(error), Ok(aaaa)) => {
                tracing::debug!(%error, %name, "DNS A lookup failed, using AAAA");
                aaaa
            }
            (Err(a_error), Err(aaaa_error)) => {
                tracing::debug!(a_error = %a_error, aaaa_error = %aaaa_error, %name, "DNS A and AAAA lookups failed");
                Vec::new()
            }
        };
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
        if rule.is_some_and(|rule| rule.raw.action.as_deref() == Some("reject")) {
            if rule.and_then(|rule| rule.raw.method.as_deref()) == Some("drop") {
                bail!("DNS query dropped by rule")
            }
            return refused_response(request, question_end);
        }
        if let Some(rule) = rule.filter(|rule| rule.raw.action.as_deref() == Some("predefined")) {
            let rcode = self::message::parse_rcode(rule.raw.rcode.as_ref())?;
            let records = rule
                .raw
                .answer
                .iter()
                .chain(&rule.raw.ns)
                .chain(&rule.raw.extra)
                .map(|record| self::message::parse_dns_record(record))
                .collect::<Result<Vec<_>>>()?;
            return predefined_response(request, question_end, rcode, &records);
        }
        let server_tag = rule
            .and_then(|rule| rule.raw.server.as_deref())
            .unwrap_or(&self.inner.final_tag);
        let server = self
            .inner
            .servers
            .get(server_tag)
            .cloned()
            .with_context(|| format!("unknown DNS server: {server_tag}"))?;
        let client_subnet = rule
            .and_then(|rule| rule.raw.client_subnet.as_deref())
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
                    rule.and_then(|rule| rule.raw.timeout.as_deref())
                        .map(parse_duration)
                        .transpose()?
                        .unwrap_or(self.inner.timeout),
                    server.query(&self.inner.http, &wire),
                )
                .await
                .context("DNS query timeout")??
            };
            validate_response(request_id, &response)?;
            if let Some(ttl) = rule.and_then(|rule| rule.raw.rewrite_ttl) {
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
        let value = if rule.is_some_and(|rule| rule.raw.disable_cache) {
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
        if rule.is_some_and(|rule| rule.raw.action.as_deref() == Some("reject")) {
            bail!("DNS lookup rejected by rule")
        }
        if let Some(rule) = rule.filter(|rule| rule.raw.action.as_deref() == Some("predefined")) {
            let rcode = self::message::parse_rcode(rule.raw.rcode.as_ref())?;
            if rcode != 0 {
                bail!("DNS lookup rejected by rule with rcode {rcode}")
            }
            let mut addresses = Vec::new();
            for record in rule.raw.answer.iter().chain(&rule.raw.ns).chain(&rule.raw.extra) {
                let record = self::message::parse_dns_record(record)?;
                match (qtype, record.kind) {
                    (1, 1) => {
                        let [a, b, c, d] = record.rdata[..] else {
                            continue;
                        };
                        addresses.push(IpAddr::from([a, b, c, d]));
                    }
                    (28, 28) => {
                        let bytes: [u8; 16] = record.rdata[..].try_into().ok().context("invalid AAAA record")?;
                        addresses.push(IpAddr::from(bytes));
                    }
                    _ => {}
                }
            }
            addresses.sort();
            addresses.dedup();
            return Ok(addresses);
        }
        let server_tag = options
            .server
            .or_else(|| rule.and_then(|rule| rule.raw.server.as_deref()));
        let client_subnet = options
            .client_subnet
            .map(str::to_owned)
            .or_else(|| {
                rule.and_then(|rule| rule.raw.client_subnet.as_deref())
                    .map(str::to_owned)
            })
            .or_else(|| self.inner.client_subnet.clone());
        if let Some(subnet) = &client_subnet {
            parse_client_subnet(subnet)?;
        }
        let query_timeout = options
            .timeout
            .or(rule
                .and_then(|rule| rule.raw.timeout.as_deref())
                .map(parse_duration)
                .transpose()?)
            .unwrap_or(self.inner.timeout);
        let rewrite_ttl = options
            .rewrite_ttl
            .or_else(|| rule.and_then(|rule| rule.raw.rewrite_ttl));
        let disable_cache = options.disable_cache || rule.is_some_and(|rule| rule.raw.disable_cache);
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
        let addresses = match value {
            CacheValue::Addresses(addresses) => addresses,
            CacheValue::Wire(_) => bail!("invalid DNS address cache entry"),
        };
        let rule_sets_guard = self
            .inner
            .rule_sets
            .as_ref()
            .map(|sets| sets.read().expect("DNS rule-set lock poisoned"));
        let Some(rule) = rule else {
            return Ok(addresses);
        };
        let has_limit = self::message::dns_rule_has_address_limit(rule, rule_sets_guard.as_deref());
        if has_limit
            && !self::message::dns_rule_address_limit_matches(
                rule,
                name,
                &addresses,
                rule_sets_guard.as_deref(),
            )
        {
            tracing::debug!(%name, %qtype, "DNS response addresses rejected by rule-set address limit");
            bail!("DNS response rejected by rule-set address limit for {name}")
        }
        Ok(addresses)
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
    fn select_rule(&self, name: &str, qtype: u16) -> Option<&self::message::CompiledDnsRule> {
        let rule_sets = self
            .inner
            .rule_sets
            .as_ref()
            .map(|sets| sets.read().expect("DNS rule-set lock poisoned"));
        self.inner
            .rules
            .iter()
            .find(|rule| dns_rule_matches(rule, name, qtype, rule_sets.as_deref()))
    }

    fn select_server(&self, name: &str, qtype: u16) -> Result<&Arc<Upstream>> {
        let tag = self
            .select_rule(name, qtype)
            .and_then(|rule| rule.raw.server.as_ref())
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

    use crate::singbox::{DnsRule, DnsServer};

    fn test_server(kind: &str, address: SocketAddr) -> DnsConfig {
        DnsConfig {
            servers: vec![DnsServer {
                r#type: kind.into(),
                tag: "test".into(),
                server: Some(address.ip().to_string()),
                server_port: Some(address.port()),
                path: None,
                detour: None,
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
        let compiled = self::message::CompiledDnsRule::compile(&rule).unwrap();
        assert!(dns_rule_matches(&compiled, "api12.example", 65, None));
        assert!(!dns_rule_matches(&compiled, "api12.example", 1, None));
        assert!(!dns_rule_matches(&compiled, "www.example", 65, None));
        assert!(dns_rule_matches(
            &self::message::CompiledDnsRule::compile(&DnsRule {
                invert: true,
                ..rule
            })
            .unwrap(),
            "www.example",
            65,
            None
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
        let r = self::message::CompiledDnsRule::compile(&DnsRule {
            domain_suffix: vec!["example.com".into()],
            ..Default::default()
        })
        .unwrap();
        assert!(dns_rule_matches(&r, "www.example.com", 1, None));
        assert!(!dns_rule_matches(&r, "badexample.com", 1, None));
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

    #[test]
    fn dns_rules_match_rule_set_tags() {
        use crate::routing::CompiledRule;
        use crate::singbox::RouteRule;
        use std::collections::HashMap;
        use std::sync::{Arc, RwLock};

        let set = vec![CompiledRule::compile(
            &RouteRule {
                domain_suffix: vec!["example.com".into()],
                ..Default::default()
            },
            &HashMap::new(),
            false,
        )
        .unwrap()];
        let mut sets = HashMap::new();
        sets.insert("geosite-cn".into(), set);
        let rule_sets = Arc::new(RwLock::new(sets));

        let rule = self::message::CompiledDnsRule::compile(&DnsRule {
            rule_set: vec!["geosite-cn".into()],
            server: Some("dns_local".into()),
            ..Default::default()
        })
        .unwrap();
        let unlocked = rule_sets.read().unwrap();
        assert!(super::dns_rule_matches(&rule, "www.example.com", 1, Some(&unlocked)));
        assert!(!super::dns_rule_matches(&rule, "www.elsewhere.net", 1, Some(&unlocked)));
        assert!(!super::dns_rule_matches(&rule, "www.example.com", 1, None));
    }

    #[tokio::test]
    async fn exchange_serves_predefined_answers_via_rule_set() {
        use crate::routing::CompiledRule;
        use crate::singbox::RouteRule;
        use std::collections::HashMap;
        use std::sync::{Arc, RwLock};

        let set = vec![CompiledRule::compile(
            &RouteRule {
                domain_suffix: vec!["ads.example".into()],
                ..Default::default()
            },
            &HashMap::new(),
            false,
        )
        .unwrap()];
        let mut sets = HashMap::new();
        sets.insert("geosite-ads".into(), set);
        let config = DnsConfig {
            servers: vec![DnsServer {
                r#type: "udp".into(),
                tag: "unused".into(),
                server: Some("127.0.0.1".into()),
                server_port: Some(1),
                path: None,
                detour: None,
            }],
            final_server: Some("unused".into()),
            disable_cache: Some(true),
            rules: vec![DnsRule {
                rule_set: vec!["geosite-ads".into()],
                action: Some("predefined".into()),
                answer: vec![". 2147483647 IN A 0.0.0.0".into()],
                ..Default::default()
            }],
            ..Default::default()
        };
        let resolver =
            DnsResolver::with_rule_sets(&config, Some(Arc::new(RwLock::new(sets)))).unwrap();
        let response = resolver
            .exchange(&build_query(9, "banner.ads.example", 1).unwrap())
            .await
            .unwrap();
        assert_eq!(response[3] & 0x0f, 0);
        let (addresses, _) = parse_response(9, 1, &response).unwrap();
        assert_eq!(addresses, vec![IpAddr::from([0, 0, 0, 0])]);
    }

    #[tokio::test]
    async fn exchange_serves_predefined_answers() {
        let config = DnsConfig {
            servers: vec![DnsServer {
                r#type: "udp".into(),
                tag: "unused".into(),
                server: Some("127.0.0.1".into()),
                server_port: Some(1),
                path: None,
                detour: None,
            }],
            final_server: Some("unused".into()),
            disable_cache: Some(true),
            rules: vec![DnsRule {
                domain_suffix: vec!["ads.example".into()],
                action: Some("predefined".into()),
                rcode: Some(serde_json::json!("NOERROR")),
                answer: vec![". 2147483647 IN A 0.0.0.0".into()],
                ..Default::default()
            }],
            ..Default::default()
        };
        let resolver = DnsResolver::new(&config).unwrap();
        let query = build_query(9, "banner.ads.example", 1).unwrap();
        let response = resolver.exchange(&query).await.unwrap();
        assert_eq!(&response[..2], &9u16.to_be_bytes());
        assert_eq!(response[3] & 0x0f, 0);
        let (addresses, _) = parse_response(9, 1, &response).unwrap();
        assert_eq!(addresses, vec![IpAddr::from([0, 0, 0, 0])]);

        let rejected = DnsConfig {
            servers: vec![DnsServer {
                r#type: "udp".into(),
                tag: "unused".into(),
                server: Some("127.0.0.1".into()),
                server_port: Some(1),
                path: None,
                detour: None,
            }],
            final_server: Some("unused".into()),
            disable_cache: Some(true),
            rules: vec![DnsRule {
                domain_suffix: vec!["nx.example".into()],
                action: Some("predefined".into()),
                rcode: Some(serde_json::json!("NXDOMAIN")),
                ..Default::default()
            }],
            ..Default::default()
        };
        let resolver = DnsResolver::new(&rejected).unwrap();
        let response = resolver
            .exchange(&build_query(9, "missing.nx.example", 1).unwrap())
            .await
            .unwrap();
        assert_eq!(response[3] & 0x0f, 3);
        assert!(resolver.lookup("missing.nx.example").await.is_err());
    }

    struct FakeDetour {
        socket: UdpSocket,
        target: std::net::SocketAddr,
    }

    impl super::transport::DnsUdpDetour for FakeDetour {
        fn exchange_udp(
            &self,
            _tag: &str,
            _destination: std::net::SocketAddr,
            request: &[u8],
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<Vec<u8>>> + Send + '_>,
        > {
            let request = request.to_vec();
            let target = self.target;
            Box::pin(async move {
                self.socket.send_to(&request, target).await?;
                let mut buffer = vec![0; 512];
                let length = self.socket.recv(&mut buffer).await?;
                buffer.truncate(length);
                Ok(buffer)
            })
        }

        fn connect_tcp(
            &self,
            _tag: &str,
            _destination: std::net::SocketAddr,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<Box<dyn super::transport::DnsIo>>> + Send + '_>,
        > {
            Box::pin(async move { bail!("fake detour does not support TCP") })
        }
    }

    #[tokio::test]
    async fn exchange_routes_udp_queries_through_detour() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let requests = Arc::new(AtomicUsize::new(0));
        let observed = requests.clone();
        tokio::spawn(async move {
            let mut buffer = [0; 512];
            for _ in 0..2 {
                let (length, peer) = socket.recv_from(&mut buffer).await.unwrap();
                observed.fetch_add(1, Ordering::Relaxed);
                let response = answer_query(&buffer[..length]);
                socket.send_to(&response, peer).await.unwrap();
            }
        });
        let mut config = test_server("udp", address);
        config.servers[0].detour = Some("proxy".into());
        config.disable_cache = Some(true);
        let detour_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let resolver = DnsResolver::new(&config).unwrap();
        resolver.set_detour(Arc::new(FakeDetour {
            socket: detour_socket,
            target: address,
        }));
        let response = resolver
            .exchange(&build_query(11, "detour.example", 1).unwrap())
            .await
            .expect("detour exchange");
        assert_eq!(response[3] & 0x0f, 0);
        let (addresses, _) = parse_response(11, 1, &response).unwrap();
        assert_eq!(addresses, vec![IpAddr::from([1, 2, 3, 4])]);
        assert_eq!(requests.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn cache_persistence_saves_and_restores_across_resolvers() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let requests = Arc::new(AtomicUsize::new(0));
        let observed = requests.clone();
        tokio::spawn(async move {
            let mut buffer = [0; 512];
            for _ in 0..2 {
                let (length, peer) = socket.recv_from(&mut buffer).await.unwrap();
                observed.fetch_add(1, Ordering::Relaxed);
                let response = answer_query(&buffer[..length]);
                socket.send_to(&response, peer).await.unwrap();
            }
        });
        let mut config = test_server("udp", address);
        config.disable_cache = Some(false);
        let resolver = DnsResolver::new(&config).unwrap();
        let path = std::env::temp_dir().join(format!(
            "xhttp-rs-dns-cache-{}.json",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        resolver
            .lookup_with_options("persisted.example", &LookupOptions::default())
            .await
            .unwrap();
        resolver.save_cache(&path);
        assert!(std::fs::read(&path).unwrap().len() > 10);

        // A fresh resolver restores the entry; the restored cache answers
        // the second lookup without touching the upstream again.
        let resolver = DnsResolver::new(&config).unwrap();
        resolver.start_persistence(&path);
        resolver
            .lookup_with_options("persisted.example", &LookupOptions::default())
            .await
            .unwrap();
        resolver
            .lookup_with_options("persisted.example", &LookupOptions::default())
            .await
            .unwrap();
        // 2 total upstream hits: first resolver, then the restored cache
        // answers both lookups.
        assert_eq!(requests.load(Ordering::Relaxed), 2);
        let _ = std::fs::remove_file(&path);
    }
}

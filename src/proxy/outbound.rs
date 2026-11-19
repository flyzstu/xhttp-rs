use crate::{
    Client,
    config::{ClientConfig, ClientTlsConfig},
    dns::DnsResolver,
    routing::{RouteOptions, Router},
    singbox::{DnsConfig, Outbound, RouteConfig},
    vless,
};
use anyhow::{Context, Result, bail};
use std::{
    collections::HashMap,
    net::IpAddr,
    net::ToSocketAddrs,
    sync::{Arc, RwLock},
};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use url::Url;

use super::direct::connect_direct;
use super::udp::to_anytls_destination;

pub(crate) use crate::util::socket;
pub(crate) use crate::util::url_host;

pub trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}
pub type BoxIo = Box<dyn Io>;

#[derive(Clone)]
pub enum Dialer {
    Direct,
    Block,
    AnyTls {
        client: anytls::Client,
    },
    Vless {
        client: Box<Client>,
        user: String,
        xudp: bool,
    },
    Group(Arc<Group>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupKind {
    Selector,
    UrlTest,
}

/// An outbound group: `Selector` forwards to a manually chosen member,
/// `UrlTest` periodically probes its members and auto-selects the fastest.
/// The `selected` state is shared so a Clash API can switch nodes at runtime.
#[derive(Clone)]
pub struct Group {
    kind: GroupKind,
    members: Vec<String>,
    selected: Arc<RwLock<String>>,
    url: Option<String>,
    interval: std::time::Duration,
    tolerance: u16,
}

impl Group {
    pub(crate) fn new(
        kind: GroupKind,
        members: Vec<String>,
        default: Option<String>,
        url: Option<String>,
        interval: Option<String>,
        tolerance: Option<u16>,
    ) -> Result<Self> {
        let selected = default
            .or_else(|| members.first().cloned())
            .context("group requires a default member")?;
        Ok(Self {
            kind,
            members,
            selected: Arc::new(RwLock::new(selected)),
            url,
            interval: crate::util::parse_duration_lenient(interval.as_deref())
                .max(std::time::Duration::from_secs(1)),
            tolerance: tolerance.unwrap_or(50),
        })
    }

    pub(crate) fn kind(&self) -> GroupKind {
        self.kind
    }

    pub(crate) fn now(&self) -> String {
        self.selected
            .read()
            .expect("group selection lock poisoned")
            .clone()
    }

    pub(crate) fn all(&self) -> &[String] {
        &self.members
    }

    pub(crate) fn select(&self, tag: &str) -> bool {
        if !self.members.iter().any(|member| member == tag) {
            return false;
        }
        *self
            .selected
            .write()
            .expect("group selection lock poisoned") = tag.to_owned();
        true
    }

    pub(crate) fn url(&self) -> Option<&str> {
        self.url.as_deref()
    }

    pub(crate) fn interval(&self) -> std::time::Duration {
        self.interval
    }

    pub(crate) fn tolerance(&self) -> u16 {
        self.tolerance
    }
}

impl Dialer {
    /// Probe latency through this dialer to a URL, returning milliseconds.
    pub(crate) async fn probe_delay(&self, url: &str) -> Option<u16> {
        let url = Url::parse(url).ok()?;
        let host = url.host_str()?.to_owned();
        let mut stream = self.connect_for_probe(&url, None).await.ok()?;
        let start = std::time::Instant::now();
        let request = format!(
            "HEAD {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            url.path(),
            host
        );
        stream.write_all(request.as_bytes()).await.ok()?;
        stream.flush().await.ok()?;
        let mut response = [0u8; 1];
        tokio::io::AsyncReadExt::read_exact(&mut stream, &mut response)
            .await
            .ok()?;
        Some(start.elapsed().as_millis().min(u16::MAX as u128) as u16)
    }

    /// A Clash-style type name for this leaf dialer.
    pub(crate) fn clash_type(&self) -> &'static str {
        match self {
            Self::Direct => "Direct",
            Self::Block => "Reject",
            Self::AnyTls { .. } => "AnyTLS",
            Self::Vless { .. } => "VLESS",
            Self::Group(_) => "Group",
        }
    }

    /// Establish a TCP stream through this dialer to a probe URL's host and
    /// port, returning the raw byte stream for a latency check.
    pub(crate) async fn connect_for_probe(
        &self,
        url: &Url,
        resolver: Option<&DnsResolver>,
    ) -> Result<BoxIo> {
        let host = url.host_str().context("probe URL has no host")?.to_owned();
        let port = url
            .port_or_known_default()
            .context("probe URL has no port")?;
        let destination = vless::Destination::Domain(host, port);
        match self {
            Self::Direct => {
                let stream =
                    connect_direct(&destination, resolver, &Default::default(), &[]).await?;
                Ok(Box::new(stream))
            }
            Self::Vless { client, user, .. } => {
                let mut stream = client.connect().await?;
                vless::write_request(&mut stream, user, &destination).await?;
                vless::read_response(&mut stream).await?;
                Ok(Box::new(stream))
            }
            Self::AnyTls { client } => {
                let destination = to_anytls_destination(&destination);
                let stream = client
                    .create_stream(&anytls::encode_address(&destination)?)
                    .await?;
                Ok(Box::new(stream))
            }
            Self::Block | Self::Group(_) => bail!("cannot probe through block/group outbound"),
        }
    }

    /// Establish the underlying connection so the first real use (e.g.
    /// rule-set prefetch) doesn't fail on lazy-connect. No-op for Direct;
    /// for AnyTLS/VLESS, creates and immediately drops a stream to trigger
    /// connection setup.
    pub(crate) async fn warm_up(&self) -> Result<()> {
        match self {
            Self::Direct | Self::Block | Self::Group(_) => Ok(()),
            Self::AnyTls { client } => {
                let destination = vless::Destination::Ip(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1)),
                    53,
                );
                let destination = to_anytls_destination(&destination);
                let mut stream = client
                    .create_stream(&anytls::encode_address(&destination)?)
                    .await?;
                stream.shutdown().await.ok();
                Ok(())
            }
            Self::Vless { client, user, .. } => {
                let destination = vless::Destination::Ip(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1)),
                    53,
                );
                let mut stream = client.connect().await?;
                vless::write_request(&mut stream, user, &destination).await?;
                vless::read_response(&mut stream).await?;
                stream.shutdown().await.ok();
                Ok(())
            }
        }
    }
}

/// Establish a TCP stream through `dialer` to `destination`.
///
/// Shared by the relay paths: Direct uses the route options (timeout, bind,
/// resolved addresses), VLESS sends a CONNECT request, and AnyTLS wraps the
/// destination in a UoT-free stream. Block/group dialers are rejected.
pub(crate) async fn dial_outbound(
    dialer: &Dialer,
    destination: &vless::Destination,
    resolver: Option<&DnsResolver>,
    options: &RouteOptions,
    resolved_addresses: &[IpAddr],
) -> Result<BoxIo> {
    match dialer {
        Dialer::Direct => Ok(Box::new(
            connect_direct(destination, resolver, options, resolved_addresses).await?,
        )),
        Dialer::AnyTls { client } => {
            let encoded = anytls::encode_address(&to_anytls_destination(destination))?;
            Ok(Box::new(client.create_stream(&encoded).await?))
        }
        Dialer::Vless { client, user, .. } => {
            let mut stream = client.connect().await?;
            vless::write_request(&mut stream, user, destination).await?;
            vless::read_response(&mut stream).await?;
            Ok(Box::new(stream))
        }
        Dialer::Block => bail!("connection blocked by outbound"),
        Dialer::Group(_) => unreachable!("group dialers are resolved before match"),
    }
}
pub async fn build_runtime(
    outbounds: Vec<Outbound>,
    route: Option<RouteConfig>,
    dns: Option<DnsConfig>,
    http_clients: Vec<crate::singbox::HttpClientConfig>,
    dns_cache_path: Option<std::path::PathBuf>,
) -> Result<super::ProxyRuntime> {
    let mut route_config = route.unwrap_or_default();
    if route_config.auto_detect_interface == Some(true) {
        route_config.default_interface = crate::linux_route::default_interface();
    }
    let default = outbounds
        .iter()
        .map(|outbound| outbound.tag.as_deref().unwrap_or(&outbound.r#type))
        .next()
        .map(str::to_owned)
        .unwrap_or_else(|| "direct".into());
    let rule_set_slot: Arc<std::sync::RwLock<HashMap<String, Vec<crate::routing::CompiledRule>>>> =
        Arc::new(std::sync::RwLock::new(HashMap::new()));
    let resolver = dns
        .as_ref()
        .map(|config| DnsResolver::with_rule_sets(config, Some(rule_set_slot.clone())))
        .transpose()?
        .map(Arc::new);
    let mut dialers = HashMap::new();
    let mut groups = HashMap::new();
    for outbound in outbounds {
        let tag = outbound
            .tag
            .clone()
            .unwrap_or_else(|| outbound.r#type.clone());
        let dialer = match outbound.r#type.as_str() {
            "selector" | "urltest" => {
                let kind = if outbound.r#type == "selector" {
                    GroupKind::Selector
                } else {
                    GroupKind::UrlTest
                };
                let group = Arc::new(Group::new(
                    kind,
                    outbound.outbounds.clone(),
                    outbound.default.clone(),
                    outbound.url.clone(),
                    outbound.interval.clone(),
                    outbound.tolerance,
                )?);
                groups.insert(tag.clone(), group.clone());
                Dialer::Group(group)
            }
            "direct" => Dialer::Direct,
            "vless" => {
                let transport = outbound
                    .transport
                    .context("VLESS outbound requires transport")?
                    .build()?;
                let tls = outbound.tls.clone().unwrap_or_default();
                let scheme = if tls.enabled { "https" } else { "http" };
                let server = outbound
                    .server
                    .as_ref()
                    .context("VLESS outbound requires server")?;
                let port = outbound
                    .server_port
                    .unwrap_or(if tls.enabled { 443 } else { 80 });
                let url_name = if tls.enabled {
                    tls.server_name.as_deref().unwrap_or(server)
                } else {
                    server
                };
                let url = format!(
                    "{scheme}://{}:{}{}",
                    url_host(url_name),
                    port,
                    transport.path
                );
                let needs_dns_ech = tls.ech.as_ref().is_some_and(|ech| {
                    ech.enabled && ech.config.is_empty() && ech.config_path.is_none()
                });
                let (ech_dns_name, ech_dns_cache) = if needs_dns_ech {
                    let query_name = tls
                        .ech
                        .as_ref()
                        .and_then(|ech| ech.query_server_name.clone())
                        .or_else(|| tls.server_name.clone())
                        .unwrap_or_else(|| server.clone());
                    let resolver = resolver
                        .as_deref()
                        .context("DNS-discovered ECH requires a DNS configuration")?;
                    (
                        Some(query_name.clone()),
                        Some(std::sync::Arc::new(crate::dns::EchCache::new(
                            resolver.clone(),
                            query_name,
                        ))),
                    )
                } else {
                    (None, None)
                };
                let client = Client::new(ClientConfig {
                    listen: String::new(),
                    server: url,
                    connect_addr: if url_name != server {
                        (server.as_str(), port).to_socket_addrs()?.next()
                    } else {
                        None
                    },
                    transport,
                    tls: ClientTlsConfig {
                        insecure: tls.insecure,
                        disable_sni: tls.disable_sni,
                        min_version: tls.min_version.clone(),
                        max_version: tls.max_version.clone(),
                        ca_certificate: tls.certificate_path,
                        ca_pem: if tls.certificate.is_empty() {
                            None
                        } else {
                            Some(tls.certificate.join("\n"))
                        },
                        certificate_public_key_sha256: tls.certificate_public_key_sha256.clone(),
                        client_certificate: if tls.client_certificate.is_empty() {
                            None
                        } else {
                            Some(tls.client_certificate.join("\n"))
                        },
                        client_certificate_path: tls.client_certificate_path.clone(),
                        client_key: if tls.client_key.is_empty() {
                            None
                        } else {
                            Some(tls.client_key.join("\n"))
                        },
                        client_key_path: tls.client_key_path.clone(),
                        http2_only: false,
                        http3: tls.alpn.iter().any(|value| value == "h3"),
                        ech_config: tls.ech.as_ref().and_then(|ech| {
                            (ech.enabled && !ech.config.is_empty()).then(|| ech.config.join("\n"))
                        }),
                        ech_config_path: tls
                            .ech
                            .as_ref()
                            .filter(|ech| ech.enabled)
                            .and_then(|ech| ech.config_path.clone()),
                        ech_config_bytes: None,
                        ech_dns_name,
                        ech_dns_cache,
                    },
                })?;
                Dialer::Vless {
                    client: Box::new(client),
                    user: outbound
                        .uuid
                        .clone()
                        .context("VLESS outbound requires uuid")?,
                    xudp: match outbound.packet_encoding.as_deref() {
                        None | Some("xudp") => true,
                        Some("") => false,
                        Some(value) => bail!("unsupported VLESS packet_encoding: {value}"),
                    },
                }
            }
            "anytls" => Dialer::AnyTls {
                client: crate::anytls::build_client(&outbound, resolver.clone())?,
            },
            "block" => Dialer::Block,
            other => bail!("unsupported outbound type: {other}"),
        };
        dialers.insert(tag, dialer);
    }
    dialers.entry("direct".into()).or_insert(Dialer::Direct);
    let dialers = Arc::new(dialers);
    let provider = Arc::new(super::DetourProvider::new(
        dialers.clone(),
        resolver.clone(),
    ));
    if let Some(resolver) = &resolver {
        resolver.set_detour(provider.clone());
    }

    let selected_groups = if let (Some(resolver), Some(path)) = (&resolver, &dns_cache_path) {
        resolver.start_persistence(path)
    } else {
        None
    };
    if let Some(selected_map) = selected_groups {
        for (group_tag, member_tag) in selected_map {
            if let Some(group) = groups.get(&group_tag)
                && group.select(&member_tag)
            {
                tracing::info!(group = %group_tag, selected = %member_tag, "restored group selection from cache");
            }
        }
    }
    if let (Some(resolver), Some(_)) = (&resolver, &dns_cache_path) {
        let groups_clone = groups.clone();
        resolver.set_selected_provider(Arc::new(move || {
            groups_clone
                .iter()
                .map(|(k, v)| (k.clone(), v.now()))
                .collect()
        }));
    }

    // Pre-warm detours referenced by http_clients before routing compilation and rule-set prefetch
    for client in &http_clients {
        if let Some(detour) = client.detour.as_deref().filter(|s| !s.is_empty())
            && let Some(dialer) = provider.dialer(detour)
        {
            tracing::info!(detour, client = %client.tag, "pre-warming http_client detour");
            for attempt in 1u8..=3 {
                match dialer.warm_up().await {
                    Ok(()) => {
                        tracing::info!(detour, "detour warmed up successfully");
                        break;
                    }
                    Err(error) if attempt < 3 => {
                        tracing::debug!(error = %format!("{error:#}"), attempt, detour, "detour warm-up retry");
                        tokio::time::sleep(std::time::Duration::from_millis(
                            300 * u64::from(attempt),
                        ))
                        .await;
                    }
                    Err(error) => {
                        tracing::warn!(error = %format!("{error:#}"), detour, "detour warm-up failed after 3 attempts");
                    }
                }
            }
        }
    }

    let prefetched = super::prefetch_rule_sets(&route_config, &http_clients, &provider).await;
    let compile_config = route_config.clone();
    let compile_default = default.clone();
    let router = Arc::new(
        tokio::task::spawn_blocking(move || {
            Router::compile_runtime_prefetched(&compile_config, compile_default, &prefetched)
        })
        .await
        .context("route compiler task failed")??,
    );
    {
        let mut slot = rule_set_slot.write().expect("rule-set slot lock poisoned");
        *slot = router
            .rule_sets()
            .read()
            .expect("route rule-set lock poisoned")
            .clone();
    }
    super::start_rule_set_updater(
        router.clone(),
        route_config,
        default,
        http_clients,
        provider.clone(),
    );
    let runtime = super::ProxyRuntime {
        dialers,
        groups: Arc::new(groups),
        router,
        resolver,
        tun_output_mark: Arc::new(RwLock::new(None)),
        clash_mode: Arc::new(RwLock::new(std::env::var("XHTTP_CLASH_MODE").ok())),
        provider,
    };
    runtime.start_url_tests();
    Ok(runtime)
}

/// Resolve an outbound tag to a leaf dialer, following selector/urltest
/// groups to their currently selected member.
pub(crate) fn resolve_grouped_dialer(
    dialers: &HashMap<String, Dialer>,
    tag: &str,
) -> Option<Dialer> {
    let mut current = tag.to_owned();
    for _ in 0..8 {
        if let Dialer::Group(group) = dialers.get(&current)? {
            current = group.now();
            continue;
        }
        return dialers.get(&current).cloned();
    }
    None
}

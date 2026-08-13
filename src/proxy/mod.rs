mod direct;
mod inbound;
mod relay;
mod route;
mod udp;

use crate::{
    Client,
    config::{ClientConfig, ClientTlsConfig},
    dns::DnsResolver,
    routing::Router,
    singbox::{DnsConfig, Outbound, RouteConfig},
    vless,
};
use anyhow::{Context, Result, bail};
use std::{
    collections::HashMap,
    net::ToSocketAddrs,
    sync::{Arc, RwLock},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use url::Url;

pub(crate) use relay::{relay_anytls_tcp, relay_anytls_udp, relay_tun_tcp, relay_tun_udp};
pub use inbound::run_socks;
pub use inbound::run_socks_with_runtime;
#[cfg(feature = "fuzzing")]
pub use udp::fuzz_socks_udp;
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
        stream.read_exact(&mut response).await.ok()?;
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
    pub(crate) async fn connect_for_probe(&self, url: &Url, resolver: Option<&DnsResolver>) -> Result<BoxIo> {
        let host = url.host_str().context("probe URL has no host")?.to_owned();
        let port = url.port_or_known_default().context("probe URL has no port")?;
        match self {
            Self::Direct => {
                let destination = vless::Destination::Domain(host, port);
                let stream = crate::proxy::direct::connect_direct(
                    &destination,
                    resolver,
                    &Default::default(),
                    &[],
                )
                .await?;
                Ok(Box::new(stream))
            }
            Self::Vless { client, user, .. } => {
                let mut stream = client.connect().await?;
                vless::write_request(
                    &mut stream,
                    user,
                    &vless::Destination::Domain(host, port),
                )
                .await?;
                vless::read_response(&mut stream).await?;
                Ok(Box::new(stream))
            }
            Self::AnyTls { client } => {
                let destination = crate::proxy::udp::to_anytls_destination(
                    &vless::Destination::Domain(host, port),
                );
                let stream = client
                    .create_stream(&anytls::encode_address(&destination)?)
                    .await?;
                Ok(Box::new(stream))
            }
            Self::Block | Self::Group(_) => bail!("cannot probe through block/group outbound"),
        }
    }
}

#[derive(Clone)]
pub struct ProxyRuntime {
    dialers: Arc<HashMap<String, Dialer>>,
    groups: Arc<HashMap<String, Arc<Group>>>,
    router: Arc<Router>,
    resolver: Option<Arc<DnsResolver>>,
    tun_output_mark: Option<u32>,
    clash_mode: Arc<RwLock<Option<String>>>,
    provider: Arc<DetourProvider>,
}

/// Resolves outbound tags to tunneled connections for `detour` DNS servers.
/// Follows selector/urltest groups to their current member, then opens a UDP
/// session (XUDP for VLESS, UoT for AnyTLS, a plain socket for direct) or a
/// TCP stream through that outbound.
pub(crate) struct DetourProvider {
    dialers: Arc<HashMap<String, Dialer>>,
    resolver: Option<Arc<DnsResolver>>,
}

impl DetourProvider {
    pub(crate) fn new(
        dialers: Arc<HashMap<String, Dialer>>,
        resolver: Option<Arc<DnsResolver>>,
    ) -> Self {
        Self { dialers, resolver }
    }

    fn resolve(&self, tag: &str) -> Option<Dialer> {
        let mut current = tag.to_owned();
        for _ in 0..8 {
            if let Dialer::Group(group) = self.dialers.get(&current)? {
                current = group.now();
                continue;
            }
            return self.dialers.get(&current).cloned();
        }
        None
    }
}

impl crate::dns::transport::DnsUdpDetour for DetourProvider {
    fn exchange_udp(
        &self,
        tag: &str,
        destination: std::net::SocketAddr,
        request: &[u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>>> + Send + '_>> {
        let tag = tag.to_owned();
        let request = request.to_vec();
        Box::pin(async move {
            self.exchange_udp_inner(&tag, destination, &request).await
        })
    }

    fn connect_tcp(
        &self,
        tag: &str,
        destination: std::net::SocketAddr,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Box<dyn crate::dns::transport::DnsIo>>> + Send + '_>> {
        let tag = tag.to_owned();
        Box::pin(async move {
            self.connect_tcp_inner(&tag, destination).await
        })
    }
}

impl DetourProvider {
    async fn exchange_udp_inner(
        &self,
        tag: &str,
        destination: std::net::SocketAddr,
        request: &[u8],
    ) -> Result<Vec<u8>> {
        let dialer = self.resolve(tag).with_context(|| format!("unknown DNS detour outbound: {tag}"))?;
        match dialer {
            Dialer::Direct => {
                let socket = crate::proxy::direct::direct_udp_socket(destination, &Default::default())?;
                socket.connect(destination).await?;
                socket.send(request).await?;
                let mut response = vec![0; u16::MAX as usize];
                let length = tokio::time::timeout(std::time::Duration::from_secs(5), socket.recv(&mut response))
                    .await
                    .context("DNS detour direct timeout")??;
                response.truncate(length);
                Ok(response)
            }
            Dialer::Vless { client, user, xudp } => {
                let destination = vless::Destination::Ip(destination.ip(), destination.port());
                let mut stream = client.connect().await?;
                vless::write_request_with_command(
                    &mut stream,
                    &user,
                    if xudp { vless::Command::Xudp } else { vless::Command::Udp },
                    &destination,
                )
                .await?;
                if xudp {
                    vless::write_xudp_packet(&mut stream, true, &destination, request).await?;
                } else {
                    stream.write_u16(request.len().try_into().context("DNS query too large")?).await?;
                    stream.write_all(request).await?;
                    stream.flush().await?;
                }
                vless::read_response(&mut stream).await?;
                let response = if xudp {
                    let (_, payload) = vless::read_xudp_packet(&mut stream).await?;
                    payload
                } else {
                    let length = stream.read_u16().await? as usize;
                    let mut response = vec![0; length];
                    stream.read_exact(&mut response).await?;
                    response
                };
                Ok(response)
            }
            Dialer::AnyTls { client } => {
                let destination = udp::to_anytls_destination(&vless::Destination::Ip(destination.ip(), destination.port()));
                let initial = anytls::encode_address(&anytls::uot::magic_destination())?;
                let mut stream = client.create_stream(&initial).await?;
                anytls::uot::write_request(
                    &mut stream,
                    &anytls::uot::Request {
                        is_connect: true,
                        destination: destination.clone(),
                    },
                )
                .await?;
                anytls::uot::write_packet(&mut stream, &destination, request, true).await?;
                let (_, payload) = anytls::uot::read_packet(&mut stream, Some(&destination)).await?;
                Ok(payload)
            }
            Dialer::Block | Dialer::Group(_) => bail!("DNS detour cannot use block/group outbound"),
        }
    }

    async fn connect_tcp_inner(
        &self,
        tag: &str,
        destination: std::net::SocketAddr,
    ) -> Result<Box<dyn crate::dns::transport::DnsIo>> {
        let dialer = self.resolve(tag).with_context(|| format!("unknown DNS detour outbound: {tag}"))?;
        let destination = vless::Destination::Ip(destination.ip(), destination.port());
        match dialer {
            Dialer::Direct => Ok(Box::new(
                crate::proxy::direct::connect_direct(&destination, self.resolver.as_deref(), &Default::default(), &[]).await?,
            )),
            Dialer::Vless { client, user, .. } => {
                let mut stream = client.connect().await?;
                vless::write_request(&mut stream, &user, &destination).await?;
                vless::read_response(&mut stream).await?;
                Ok(Box::new(stream))
            }
            Dialer::AnyTls { client } => {
                let destination = udp::to_anytls_destination(&destination);
                let stream = client
                    .create_stream(&anytls::encode_address(&destination)?)
                    .await?;
                Ok(Box::new(stream))
            }
            Dialer::Block | Dialer::Group(_) => bail!("DNS detour cannot use block/group outbound"),
        }
    }

    /// Fetch a URL over HTTP/1.1 through the outbound `tag`. HTTPS URLs are
    /// wrapped in TLS with native roots; redirects are followed up to five
    /// hops; the body is limited to 64 MiB.
    pub(crate) async fn fetch_url(&self, tag: &str, url: &str) -> Result<Vec<u8>> {
        self.fetch_url_inner(tag, url, 0).await
    }

    /// Fetch a URL with conditional request support: `etag` is sent as
    /// `If-None-Match`, and a 304 response yields `(empty, etag, true)`.
    pub(crate) async fn fetch_url_etag(
        &self,
        tag: &str,
        url: &str,
        etag: Option<&str>,
    ) -> Result<(Vec<u8>, Option<String>, bool)> {
        let (data, headers, status) = self
            .fetch_url_with_etag(tag, url, etag, 0)
            .await?;
        let new_etag = headers
            .iter()
            .find_map(|(name, value)| {
                name.eq_ignore_ascii_case("etag").then(|| value.clone())
            });
        Ok((data, new_etag, status == 304))
    }

    async fn fetch_url_with_etag(
        &self,
        tag: &str,
        url: &str,
        etag: Option<&str>,
        redirects: u8,
    ) -> Result<(Vec<u8>, Vec<(String, String)>, u16)> {
        if redirects > 5 {
            bail!("HTTP redirect limit exceeded for {url}")
        }
        let url = Url::parse(url).context("invalid rule-set URL")?;
        let scheme = url.scheme();
        if !matches!(scheme, "http" | "https") {
            bail!("unsupported rule-set URL scheme: {scheme}")
        }
        let host = url
            .host_str()
            .context("rule-set URL has no host")?
            .to_owned();
        let port = url.port_or_known_default().context("rule-set URL has no port")?;
        let path = if url.path().is_empty() {
            "/".to_owned()
        } else {
            url.path().to_owned()
        };
        let query = url.query().map(|query| format!("?{query}")).unwrap_or_default();
        let address = tokio::net::lookup_host((host.as_str(), port))
            .await?
            .next()
            .context("rule-set host did not resolve")?;
        let tcp = self
            .connect_tcp_inner(tag, address)
            .await
            .context("connect rule-set host through outbound")?;
        let mut stream: Box<dyn crate::dns::transport::DnsIo> = if scheme == "https" {
            let mut roots = rustls::RootCertStore::empty();
            for certificate in rustls_native_certs::load_native_certs().certs {
                roots.add(certificate).context("add native root certificate")?;
            }
            let connector = tokio_rustls::TlsConnector::from(Arc::new(
                rustls::ClientConfig::builder()
                    .with_root_certificates(roots)
                    .with_no_client_auth(),
            ));
            let name = rustls::pki_types::ServerName::try_from(host.clone())
                .context("invalid rule-set host")?;
            Box::new(connector.connect(name, tcp).await.context("TLS handshake with rule-set host")?)
        } else {
            tcp
        };
        let conditional = etag
            .filter(|value| !value.is_empty())
            .map(|value| format!("If-None-Match: {value}\r\n"))
            .unwrap_or_default();
        let request = format!(
            "GET {path}{query} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: xhttp-rs\r\nConnection: close\r\nAccept: */*\r\n{conditional}\r\n"
        );
        stream.write_all(request.as_bytes()).await?;
        stream.flush().await?;
        let response = read_http_response(&mut *stream).await?;
        let (status, headers, body) = response;
        if matches!(status, 301 | 302 | 303 | 307 | 308) {
            let location = headers
                .iter()
                .find_map(|(name, value)| {
                    name.eq_ignore_ascii_case("location").then(|| value.clone())
                })
                .context("redirect response has no Location header")?;
            let next = url
                .join(&location)
                .context("invalid redirect Location")?
                .to_string();
            return Box::pin(self.fetch_url_with_etag(tag, &next, etag, redirects + 1)).await;
        }
        if status != 200 && status != 304 {
            bail!("rule-set download returned HTTP {status}")
        }
        if body.len() > 64 * 1024 * 1024 {
            bail!("rule-set download exceeds 64 MiB")
        }
        Ok((body, headers, status))
    }

    async fn fetch_url_inner(&self, tag: &str, url: &str, redirects: u8) -> Result<Vec<u8>> {
        let (body, _, status) = self.fetch_url_with_etag(tag, url, None, redirects).await?;
        if status == 304 {
            bail!("unexpected 304 response without a conditional request")
        }
        Ok(body)
    }
}

/// Read an HTTP/1.1 response: status line, headers, and body. Handles
/// `Content-Length`, chunked transfer encoding, and close-delimited bodies./// Read an HTTP/1.1 response: status line, headers, and body. Handles
/// `Content-Length`, chunked transfer encoding, and close-delimited bodies.
async fn read_http_response(
    stream: &mut dyn crate::dns::transport::DnsIo,
) -> Result<(u16, Vec<(String, String)>, Vec<u8>)> {
    use tokio::io::AsyncBufReadExt;
    let mut reader = tokio::io::BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).await?;
    let mut parts = line.split_whitespace();
    let _version = parts.next().context("missing HTTP version")?;
    let status: u16 = parts
        .next()
        .context("missing HTTP status")?
        .parse()
        .context("invalid HTTP status")?;
    let mut headers = Vec::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        let line = line.trim_end_matches("\r\n");
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_owned(), value.trim().to_owned()));
        }
    }
    let content_length = headers.iter().find_map(|(name, value)| {
        name.eq_ignore_ascii_case("content-length")
            .then(|| value.parse::<usize>().ok())
            .flatten()
    });
    let chunked = headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("transfer-encoding")
            && value.to_ascii_lowercase().contains("chunked")
    });
    let mut body = Vec::new();
    if let Some(length) = content_length {
        body.reserve(length);
        reader.take(length as u64).read_to_end(&mut body).await?;
    } else if chunked {
        loop {
            let mut size_line = String::new();
            reader.read_line(&mut size_line).await?;
            let size = usize::from_str_radix(size_line.trim().trim_end_matches(";"), 16)
                .context("invalid chunk size")?;
            if size == 0 {
                let mut trailer = Vec::new();
                reader.read_until(b'\n', &mut trailer).await?;
                reader.read_until(b'\n', &mut trailer).await?;
                break;
            }
            let start = body.len();
            body.resize(start + size, 0);
            reader.read_exact(&mut body[start..]).await?;
            let mut crlf = [0u8; 2];
            reader.read_exact(&mut crlf).await?;
        }
    } else {
        reader.read_to_end(&mut body).await?;
    }
    Ok((status, headers, body))
}

pub async fn build_runtime(
    outbounds: Vec<Outbound>,
    route: Option<RouteConfig>,
    dns: Option<DnsConfig>,
    http_clients: Vec<crate::singbox::HttpClientConfig>,
    dns_cache_path: Option<std::path::PathBuf>,
) -> Result<ProxyRuntime> {
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
    if let (Some(resolver), Some(path)) = (&resolver, dns_cache_path) {
        resolver.start_persistence(&path);
    }
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
                let ech_config_bytes =
                    if let Some(ech) = tls.ech.as_ref().filter(|ech| {
                        ech.enabled && ech.config.is_empty() && ech.config_path.is_none()
                    }) {
                        let query_name = ech
                            .query_server_name
                            .as_deref()
                            .or(tls.server_name.as_deref())
                            .unwrap_or(server);
                        Some(
                            resolver
                                .as_deref()
                                .context("DNS-discovered ECH requires a DNS configuration")?
                                .ech_config(query_name)
                                .await?,
                        )
                    } else {
                        None
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
                        ech_config_bytes,
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
    let provider = Arc::new(DetourProvider::new(dialers.clone(), resolver.clone()));
    if let Some(resolver) = &resolver {
        resolver.set_detour(provider.clone());
    }
    let prefetched = prefetch_rule_sets(&route_config, &http_clients, &provider).await;
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
        let mut slot = rule_set_slot
            .write()
            .expect("rule-set slot lock poisoned");
        *slot = router
            .rule_sets()
            .read()
            .expect("route rule-set lock poisoned")
            .clone();
    }
    start_rule_set_updater(
        router.clone(),
        route_config,
        default,
        http_clients,
        provider.clone(),
    );
    let runtime = ProxyRuntime {
        dialers,
        groups: Arc::new(groups),
        router,
        resolver,
        tun_output_mark: None,
        clash_mode: Arc::new(RwLock::new(std::env::var("XHTTP_CLASH_MODE").ok())),
    };
    runtime.start_url_tests();
    Ok(runtime)
}

impl ProxyRuntime {
    pub(crate) fn set_tun_output_mark(&mut self, mark: u32) {
        self.tun_output_mark = Some(mark);
    }

    pub(crate) fn rule_set_ip_cidrs(&self, tags: &[String]) -> Result<Vec<ipnet::IpNet>> {
        self.router.rule_set_ip_cidrs(tags)
    }

    /// Resolve a dialer by tag, following `selector`/`urltest` groups to their
    /// currently selected member.
    pub(crate) fn dialer_for(&self, tag: &str) -> Option<Dialer> {
        resolve_grouped_dialer(&self.dialers, tag)
    }

    #[allow(dead_code)]
    pub(crate) fn group(&self, tag: &str) -> Option<&Arc<Group>> {
        self.groups.get(tag)
    }

    pub(crate) fn clash_mode(&self) -> Option<String> {
        self.clash_mode
            .read()
            .expect("clash mode lock poisoned")
            .clone()
    }

    #[allow(dead_code)]
    pub(crate) fn set_clash_mode(&self, mode: Option<String>) {
        *self
            .clash_mode
            .write()
            .expect("clash mode lock poisoned") = mode;
    }

    /// Set the route fallback outbound (the GLOBAL selection in a Clash API).
    pub(crate) fn set_final_outbound(&self, tag: &str) {
        self.router.set_final_outbound(tag);
    }

    /// Fetch a URL through the outbound `tag`, used for the Clash dashboard
    /// `external_ui_download_detour`.
    pub(crate) async fn fetch_url_via(&self, tag: &str, url: &str) -> Result<Vec<u8>> {
        self.provider.fetch_url(tag, url).await
    }

    #[allow(dead_code)]
    pub(crate) fn groups(&self) -> &HashMap<String, Arc<Group>> {
        &self.groups
    }

    /// All outbound tags in declaration-independent order: groups then leaves.
    pub(crate) fn outbound_tags(&self) -> Vec<String> {
        let mut tags: Vec<String> = self.groups.keys().cloned().collect();
        for tag in self.dialers.keys() {
            if !self.groups.contains_key(tag) {
                tags.push(tag.clone());
            }
        }
        tags
    }

    pub(crate) fn is_group(&self, tag: &str) -> bool {
        self.groups.contains_key(tag)
    }

    /// Spawn a background task for each `urltest` group that periodically
    /// probes its members and auto-selects the fastest within tolerance.
    fn start_url_tests(&self) {
        let runtime = self.clone();
        for (tag, group) in self.groups.iter() {
            if group.kind() != GroupKind::UrlTest {
                continue;
            }
            let Some(url) = group.url().map(str::to_owned) else {
                continue;
            };
            let interval = group.interval();
            let tag = tag.clone();
            let group = group.clone();
            let runtime = runtime.clone();
            tokio::spawn(async move {
                loop {
                    run_url_test(&runtime, &tag, &group, &url).await;
                    tokio::time::sleep(interval).await;
                }
            });
        }
    }
}

async fn run_url_test(
    runtime: &ProxyRuntime,
    tag: &str,
    group: &Arc<Group>,
    url: &str,
) {
    let tolerance = group.tolerance();
    let mut best: Option<(String, u16)> = None;
    for member in group.all() {
        let Some(dialer) = runtime.dialer_for(member) else {
            continue;
        };
        let Some(delay) = dialer.probe_delay(url).await else {
            continue;
        };
        match &best {
            Some((_, best_delay)) if delay + tolerance >= *best_delay => {}
            _ => best = Some((member.clone(), delay)),
        }
    }
    if let Some((best_tag, _)) = best {
        let _ = group.select(&best_tag);
        tracing::debug!(%tag, %best_tag, "urltest group updated");
    }
}

fn start_rule_set_updater(
    router: Arc<Router>,
    config: RouteConfig,
    default_outbound: String,
    http_clients: Vec<crate::singbox::HttpClientConfig>,
    provider: Arc<DetourProvider>,
) {
    let update_interval = config
        .rule_set
        .iter()
        .filter(|set| set.r#type == "remote" || set.update_interval.is_some())
        .map(|set| {
            let minimum = if set.r#type == "remote" { 60 } else { 1 };
            parse_duration(set.update_interval.as_deref().or(Some("24h")))
                .max(std::time::Duration::from_secs(minimum))
        })
        .min();
    let Some(update_interval) = update_interval else {
        return;
    };
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(update_interval).await;
            let config = config.clone();
            let default_outbound = default_outbound.clone();
            let http_clients = http_clients.clone();
            let prefetched = prefetch_rule_sets(&config, &http_clients, &provider).await;
            match tokio::task::spawn_blocking(move || {
                Router::compile_runtime_prefetched(&config, default_outbound, &prefetched)
            })
            .await
            {
                Ok(Ok(updated)) => router.replace_from(updated),
                Ok(Err(error)) => tracing::warn!(%error, "failed to refresh route rule-sets"),
                Err(error) => tracing::warn!(%error, "route rule-set refresh task failed"),
            }
        }
    });
}

/// Download remote rule-sets through the configured `default_http_client`
/// detour before the router compiles them. Tags whose fetch fails are left
/// out; the compiler falls back to its direct-download and disk-cache paths
/// for those.
async fn prefetch_rule_sets(
    route: &RouteConfig,
    http_clients: &[crate::singbox::HttpClientConfig],
    provider: &DetourProvider,
) -> HashMap<String, Vec<u8>> {
    let Some(default_http_client) = route
        .default_http_client
        .as_deref()
        .filter(|tag| !tag.is_empty())
    else {
        return HashMap::new();
    };
    let Some(client) = http_clients.iter().find(|client| client.tag == default_http_client) else {
        tracing::warn!(%default_http_client, "default_http_client not found; rule-set downloads will go direct");
        return HashMap::new();
    };
    let Some(detour) = client.detour.as_deref().filter(|tag| !tag.is_empty()) else {
        return HashMap::new();
    };
    let mut prefetched = HashMap::new();
    for set in route.rule_set.iter().filter(|set| set.r#type == "remote") {
        let Some(url) = set.url.as_deref() else {
            continue;
        };
        let Ok(format) = crate::routing::rule_set_format_for(set, url) else {
            continue;
        };
        let cache_path = crate::routing::rule_set_cache_path(url, format);
        let cached_etag = std::fs::read(cache_path.with_extension("etag"))
            .ok()
            .map(|bytes| String::from_utf8_lossy(&bytes).trim().to_owned())
            .filter(|value| !value.is_empty());
        match provider.fetch_url_etag(detour, url, cached_etag.as_deref()).await {
            Ok((data, new_etag, not_modified)) => {
                if not_modified {
                    tracing::debug!(tag = %set.tag, "remote rule-set not modified");
                    if let Ok(data) = std::fs::read(&cache_path) {
                        prefetched.insert(set.tag.clone(), data);
                    }
                    continue;
                }
                tracing::info!(
                    tag = %set.tag,
                    bytes = data.len(),
                    "prefetched remote rule-set through http_client"
                );
                if let Err(error) = crate::routing::write_rule_set_cache(&cache_path, &data) {
                    tracing::warn!(%error, tag = %set.tag, "failed to write rule-set cache");
                }
                if let Some(etag) = new_etag
                    && let Err(error) = std::fs::write(cache_path.with_extension("etag"), etag)
                {
                    tracing::warn!(%error, tag = %set.tag, "failed to write rule-set etag");
                }
                prefetched.insert(set.tag.clone(), data);
            }
            Err(error) => tracing::warn!(
                %error,
                tag = %set.tag,
                "failed to prefetch remote rule-set through http_client; falling back to direct download"
            ),
        }
    }
    prefetched
}

pub(crate) fn parse_duration(value: Option<&str>) -> std::time::Duration {
    crate::util::parse_duration_lenient(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::udp::{encode_socks_udp, parse_socks_udp, udp_response_proxy_destination};
    use crate::Server;
    use crate::config::{Mode, ServerConfig, TransportConfig};
    use crate::routing::RouteOptions;
    use crate::singbox::{Inbound, Outbound, XHttpTransport};
    use crate::vless;
    use std::net::{IpAddr, SocketAddr};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream, UdpSocket};

    #[test]
    fn selector_group_selects_members_and_defaults_to_first() {
        let group = Group::new(
            GroupKind::Selector,
            vec!["a".into(), "b".into()],
            None,
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(group.kind(), GroupKind::Selector);
        assert_eq!(group.now(), "a");
        assert_eq!(group.all(), &["a", "b"]);
        assert!(group.select("b"));
        assert_eq!(group.now(), "b");
        assert!(!group.select("missing"));
        assert_eq!(group.now(), "b");
    }

    #[test]
    fn selector_group_honors_default_member() {
        let group = Group::new(
            GroupKind::Selector,
            vec!["a".into(), "b".into()],
            Some("b".into()),
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(group.now(), "b");
    }

    #[test]
    fn url_test_group_defaults_and_exposes_probe_params() {
        let group = Group::new(
            GroupKind::UrlTest,
            vec!["a".into(), "b".into()],
            None,
            Some("http://gstatic.com/generate_204".into()),
            Some("5m".into()),
            Some(80),
        )
        .unwrap();
        assert_eq!(group.kind(), GroupKind::UrlTest);
        assert_eq!(group.now(), "a");
        assert_eq!(group.url(), Some("http://gstatic.com/generate_204"));
        assert_eq!(group.interval(), std::time::Duration::from_secs(300));
        assert_eq!(group.tolerance(), 80);
        assert!(group.select("b"));
        assert_eq!(group.now(), "b");
    }

    #[test]
    fn group_requires_a_default_member() {
        assert!(Group::new(GroupKind::Selector, vec![], None, None, None, None).is_err());
    }

    #[test]
    fn udp_domain_unmapping_can_be_disabled() {
        let requested = vless::Destination::Domain("example.com".into(), 53);
        let source = vless::Destination::Ip("192.0.2.1".parse().unwrap(), 53);
        assert_eq!(
            udp_response_proxy_destination(&requested, &source, &RouteOptions::default()),
            requested
        );
        assert_eq!(
            udp_response_proxy_destination(
                &requested,
                &source,
                &RouteOptions {
                    udp_disable_domain_unmapping: true,
                    ..Default::default()
                }
            ),
            source
        );
    }
    #[tokio::test]
    async fn socks_routes_to_direct_outbound() {
        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = echo.accept().await.unwrap();
            let (mut r, mut w) = s.split();
            let _ = tokio::io::copy(&mut r, &mut w).await;
        });
        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen = probe.local_addr().unwrap();
        drop(probe);
        let inbound = Inbound {
            r#type: "socks".into(),
            listen: Some("127.0.0.1".into()),
            listen_port: Some(listen.port()),
            ..Default::default()
        };
        let outbound = Outbound {
            r#type: "direct".into(),
            tag: Some("direct".into()),
            ..Default::default()
        };
        let task = tokio::spawn(run_socks(inbound, vec![outbound], None, None, Vec::new(), None));
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let mut client = TcpStream::connect(listen).await.unwrap();
        client.write_all(&[5, 1, 0]).await.unwrap();
        let mut hello = [0; 2];
        client.read_exact(&mut hello).await.unwrap();
        assert_eq!(hello, [5, 0]);
        let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
        request.extend(target.port().to_be_bytes());
        client.write_all(&request).await.unwrap();
        let mut reply = [0; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], 0);
        client.write_all(b"route").await.unwrap();
        let mut data = [0; 5];
        client.read_exact(&mut data).await.unwrap();
        assert_eq!(&data, b"route");
        task.abort();
    }
    #[tokio::test]
    async fn socks_routes_through_selector_outbound() {
        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = echo.accept().await.unwrap();
            let (mut r, mut w) = s.split();
            let _ = tokio::io::copy(&mut r, &mut w).await;
        });
        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen = probe.local_addr().unwrap();
        drop(probe);
        let inbound = Inbound {
            r#type: "socks".into(),
            listen: Some("127.0.0.1".into()),
            listen_port: Some(listen.port()),
            ..Default::default()
        };
        let outbounds = vec![
            Outbound {
                r#type: "direct".into(),
                tag: Some("direct".into()),
                ..Default::default()
            },
            Outbound {
                r#type: "selector".into(),
                tag: Some("proxy".into()),
                outbounds: vec!["direct".into()],
                default: Some("direct".into()),
                ..Default::default()
            },
        ];
        let route = crate::singbox::RouteConfig {
            final_outbound: Some("proxy".into()),
            ..Default::default()
        };
        let task = tokio::spawn(run_socks(inbound, outbounds, Some(route), None, Vec::new(), None));
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let mut client = TcpStream::connect(listen).await.unwrap();
        client.write_all(&[5, 1, 0]).await.unwrap();
        let mut hello = [0; 2];
        client.read_exact(&mut hello).await.unwrap();
        assert_eq!(hello, [5, 0]);
        let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
        request.extend(target.port().to_be_bytes());
        client.write_all(&request).await.unwrap();
        let mut reply = [0; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], 0);
        client.write_all(b"via-selector").await.unwrap();
        let mut data = [0; 12];
        client.read_exact(&mut data).await.unwrap();
        assert_eq!(&data, b"via-selector");
        task.abort();
    }
    #[tokio::test]
    async fn http_proxy_rewrites_absolute_form() {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = target.accept().await.unwrap();
            let mut b = vec![0; 1024];
            let n = s.read(&mut b).await.unwrap();
            assert!(
                std::str::from_utf8(&b[..n])
                    .unwrap()
                    .starts_with("GET /hello HTTP/1.1")
            );
            s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await
                .unwrap();
        });
        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen = probe.local_addr().unwrap();
        drop(probe);
        let inbound = Inbound {
            r#type: "http".into(),
            listen: Some("127.0.0.1".into()),
            listen_port: Some(listen.port()),
            ..Default::default()
        };
        let outbound = Outbound {
            r#type: "direct".into(),
            tag: Some("direct".into()),
            ..Default::default()
        };
        let task = tokio::spawn(run_socks(inbound, vec![outbound], None, None, Vec::new(), None));
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let mut client = TcpStream::connect(listen).await.unwrap();
        client
            .write_all(
                format!("GET http://{target_addr}/hello HTTP/1.1\r\nHost: {target_addr}\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert!(response.ends_with(b"\r\n\r\nok"));
        task.abort();
    }

    #[tokio::test]
    async fn socks_udp_traverses_vless_xhttp() {
        let udp_echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_target = udp_echo.local_addr().unwrap();
        tokio::spawn(async move {
            let mut data = [0; 2048];
            loop {
                let (length, peer) = udp_echo.recv_from(&mut data).await.unwrap();
                udp_echo.send_to(&data[..length], peer).await.unwrap();
            }
        });

        let xhttp_probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let xhttp_addr = xhttp_probe.local_addr().unwrap();
        drop(xhttp_probe);
        let user = "e07c0f3b-5ff4-4fd7-833b-df2f4cc90963";
        let transport = TransportConfig {
            mode: Mode::PacketUp,
            padding_min: 8,
            padding_max: 8,
            packet_interval_ms: 0,
            ..Default::default()
        };
        let xhttp_task = tokio::spawn(
            Server::new(ServerConfig {
                listen: xhttp_addr.to_string(),
                target: String::new(),
                users: vec![user.into()],
                transport: transport.clone(),
                tls: None,
            })
            .unwrap()
            .run(),
        );

        let proxy_probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_probe.local_addr().unwrap();
        drop(proxy_probe);
        let inbound = Inbound {
            r#type: "socks".into(),
            tag: Some("socks-in".into()),
            listen: Some("127.0.0.1".into()),
            listen_port: Some(proxy_addr.port()),
            ..Default::default()
        };
        let outbound = Outbound {
            r#type: "vless".into(),
            tag: Some("proxy".into()),
            server: Some("127.0.0.1".into()),
            server_port: Some(xhttp_addr.port()),
            uuid: Some(user.into()),
            transport: Some(XHttpTransport {
                r#type: "xhttp".into(),
                path: Some("/xhttp".into()),
                mode: Some(Mode::PacketUp),
                x_padding_bytes: Some(crate::singbox::XHttpRange { from: 8, to: 8 }),
                sc_min_posts_interval_ms: Some(crate::singbox::XHttpRange { from: 0, to: 0 }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let proxy_task = tokio::spawn(run_socks(inbound, vec![outbound], None, None, Vec::new(), None));
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let mut control = TcpStream::connect(proxy_addr).await.unwrap();
        control.write_all(&[5, 1, 0]).await.unwrap();
        let mut method = [0; 2];
        control.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [5, 0]);
        control
            .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let mut prefix = [0; 4];
        control.read_exact(&mut prefix).await.unwrap();
        assert_eq!(&prefix[..3], &[5, 0, 0]);
        let relay = match prefix[3] {
            1 => {
                let mut rest = [0; 6];
                control.read_exact(&mut rest).await.unwrap();
                SocketAddr::new(
                    IpAddr::from(<[u8; 4]>::try_from(&rest[..4]).unwrap()),
                    u16::from_be_bytes([rest[4], rest[5]]),
                )
            }
            value => panic!("unexpected relay address type {value}"),
        };
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let request = encode_socks_udp(
            &vless::Destination::Ip(udp_target.ip(), udp_target.port()),
            b"udp-over-xhttp",
        )
        .unwrap();
        client.send_to(&request, relay).await.unwrap();
        let mut response = [0; 2048];
        let (length, _) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client.recv_from(&mut response),
        )
        .await
        .unwrap()
        .unwrap();
        let (_, payload) = parse_socks_udp(&response[..length]).unwrap();
        assert_eq!(payload, b"udp-over-xhttp");
        proxy_task.abort();
        xhttp_task.abort();
    }

    #[tokio::test]
    async fn http_response_parser_handles_content_length() {
        let (client, mut server) = tokio::io::duplex(1024);
        tokio::spawn(async move {
            server
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
                .await
                .unwrap();
        });
        let (status, headers, body) = read_http_response(&mut (Box::new(client) as Box<dyn crate::dns::transport::DnsIo>)).await.unwrap();
        assert_eq!(status, 200);
        assert!(headers.iter().any(|(name, value)| name.eq_ignore_ascii_case("content-length") && value == "5"));
        assert_eq!(body, b"hello");
    }

    #[tokio::test]
    async fn http_response_parser_handles_chunked_encoding() {
        let (client, mut server) = tokio::io::duplex(1024);
        tokio::spawn(async move {
            server
                .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n")
                .await
                .unwrap();
        });
        let (status, _, body) = read_http_response(&mut (Box::new(client) as Box<dyn crate::dns::transport::DnsIo>)).await.unwrap();
        assert_eq!(status, 200);
        assert_eq!(body, b"hello world");
    }

    #[tokio::test]
    async fn http_response_parser_handles_close_delimited_body() {
        let (client, mut server) = tokio::io::duplex(1024);
        tokio::spawn(async move {
            server
                .write_all(b"HTTP/1.1 200 OK\r\n\r\nbody until close")
                .await
                .unwrap();
            server.shutdown().await.unwrap();
        });
        let (status, _, body) = read_http_response(&mut (Box::new(client) as Box<dyn crate::dns::transport::DnsIo>)).await.unwrap();
        assert_eq!(status, 200);
        assert_eq!(body, b"body until close");
    }

    #[tokio::test]
    async fn fetch_url_etag_returns_body_then_not_modified() {
        use tokio::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = vec![0; 4096];
            let _ = stream.read(&mut request).await.unwrap();
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nETag: \"v1\"\r\n\r\nhello",
                )
                .await
                .unwrap();
        });
        let mut dialers = HashMap::new();
        dialers.insert("direct".into(), Dialer::Direct);
        let provider = DetourProvider::new(Arc::new(dialers), None);
        let url = format!("http://{address}/rules.json");
        let (body, etag, not_modified) = provider.fetch_url_etag("direct", &url, None).await.unwrap();
        assert_eq!(body, b"hello");
        assert_eq!(etag.as_deref(), Some("\"v1\""));
        assert!(!not_modified);

        // Second request with the etag gets 304 from a conditional server.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = vec![0; 4096];
            let _ = stream.read(&mut request).await.unwrap();
            stream
                .write_all(b"HTTP/1.1 304 Not Modified\r\nETag: \"v1\"\r\n\r\n")
                .await
                .unwrap();
        });
        let (body, etag, not_modified) = provider
            .fetch_url_etag("direct", &format!("http://{address}/rules.json"), Some("\"v1\""))
            .await
            .unwrap();
        assert!(body.is_empty());
        assert_eq!(etag.as_deref(), Some("\"v1\""));
        assert!(not_modified);
    }

    #[tokio::test]
    async fn fetch_url_etag_follows_redirects() {
        use tokio::net::TcpListener;
        let first = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let second = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let first_addr = first.local_addr().unwrap();
        let second_addr = second.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = first.accept().await.unwrap();
            let mut request = vec![0; 4096];
            let _ = stream.read(&mut request).await.unwrap();
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 302 Found\r\nLocation: http://{second_addr}/final\r\nContent-Length: 0\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
        });
        tokio::spawn(async move {
            let (mut stream, _) = second.accept().await.unwrap();
            let mut request = vec![0; 4096];
            let _ = stream.read(&mut request).await.unwrap();
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nfinal!")
                .await
                .unwrap();
        });
        let mut dialers = HashMap::new();
        dialers.insert("direct".into(), Dialer::Direct);
        let provider = DetourProvider::new(Arc::new(dialers), None);
        let (body, _, not_modified) = provider
            .fetch_url_etag("direct", &format!("http://{first_addr}/start"), None)
            .await
            .unwrap();
        assert_eq!(body, b"final!");
        assert!(!not_modified);
    }
}

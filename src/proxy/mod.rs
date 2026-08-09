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
}

pub async fn build_runtime(
    outbounds: Vec<Outbound>,
    route: Option<RouteConfig>,
    dns: Option<DnsConfig>,
) -> Result<ProxyRuntime> {
    let resolver = dns
        .as_ref()
        .map(DnsResolver::new)
        .transpose()?
        .map(Arc::new);
    let mut dialers = HashMap::new();
    let mut groups = HashMap::new();
    let mut first_tag = None;
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
        if first_tag.is_none() {
            first_tag = Some(tag.clone())
        }
        dialers.insert(tag, dialer);
    }
    dialers.entry("direct".into()).or_insert(Dialer::Direct);
    let default = first_tag.unwrap_or_else(|| "direct".into());
    let mut route_config = route.unwrap_or_default();
    if route_config.auto_detect_interface == Some(true) {
        route_config.default_interface = crate::linux_route::default_interface();
    }
    let compile_config = route_config.clone();
    let compile_default = default.clone();
    let router = Arc::new(
        tokio::task::spawn_blocking(move || {
            Router::compile_runtime(&compile_config, compile_default)
        })
        .await
        .context("route compiler task failed")??,
    );
    start_rule_set_updater(router.clone(), route_config, default);
    let runtime = ProxyRuntime {
        dialers: Arc::new(dialers),
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

fn start_rule_set_updater(router: Arc<Router>, config: RouteConfig, default_outbound: String) {
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
            match tokio::task::spawn_blocking(move || {
                Router::compile_runtime(&config, default_outbound)
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
        let task = tokio::spawn(run_socks(inbound, vec![outbound], None, None));
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
        let task = tokio::spawn(run_socks(inbound, outbounds, Some(route), None));
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
        let task = tokio::spawn(run_socks(inbound, vec![outbound], None, None));
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
        let proxy_task = tokio::spawn(run_socks(inbound, vec![outbound], None, None));
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
}

mod detour;
mod direct;
mod inbound;
#[cfg(target_os = "linux")]
pub mod redirect;
mod relay;
mod route;
#[cfg(target_os = "linux")]
pub mod tproxy;
mod udp;
pub(crate) mod udp_nat;

mod outbound;

use crate::{dns::DnsResolver, routing::Router, singbox::RouteConfig};
use anyhow::Result;
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

pub(crate) use detour::DetourProvider;
pub use inbound::run_socks;
pub use inbound::run_socks_with_runtime;
#[cfg(target_os = "linux")]
pub(crate) use relay::relay_streamed_tcp;
pub(crate) use relay::{relay_anytls_tcp, relay_anytls_udp, relay_tun_tcp, relay_tun_udp};
#[cfg(feature = "fuzzing")]
pub use udp::fuzz_socks_udp;

// The outbound stack (Dialer, Group, build_runtime, helpers) lives in
// `proxy::outbound`; these re-exports preserve the old paths.
pub use outbound::{BoxIo, Dialer, Group, GroupKind, Io, build_runtime};
pub(crate) use outbound::{dial_outbound, resolve_grouped_dialer, socket};

pub(crate) fn parse_duration(value: Option<&str>) -> std::time::Duration {
    crate::util::parse_duration_lenient(value)
}

#[derive(Clone)]
pub struct ProxyRuntime {
    dialers: Arc<HashMap<String, Dialer>>,
    groups: Arc<HashMap<String, Arc<Group>>>,
    router: Arc<Router>,
    resolver: Option<Arc<DnsResolver>>,
    tun_output_mark: Arc<RwLock<Option<u32>>>,
    clash_mode: Arc<RwLock<Option<String>>>,
    provider: Arc<DetourProvider>,
}

impl ProxyRuntime {
    pub(crate) fn set_tun_output_mark(&self, mark: u32) {
        *self
            .tun_output_mark
            .write()
            .expect("tun output mark lock poisoned") = Some(mark);
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
        *self.clash_mode.write().expect("clash mode lock poisoned") = mode;
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

async fn run_url_test(runtime: &ProxyRuntime, tag: &str, group: &Arc<Group>, url: &str) {
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
    let Some(client) = http_clients
        .iter()
        .find(|client| client.tag == default_http_client)
    else {
        tracing::warn!(%default_http_client, "default_http_client not found; rule-set downloads will go direct");
        return HashMap::new();
    };
    let Some(detour) = client.detour.as_deref().filter(|tag| !tag.is_empty()) else {
        return HashMap::new();
    };
    // Warm up the detour so the first real request doesn't fail on
    // lazy-connect. Retry with backoff; proceed anyway if it fails.
    if let Some(dialer) = provider.dialer(detour) {
        for attempt in 1u8..=3 {
            match dialer.warm_up().await {
                Ok(()) => break,
                Err(error) if attempt < 3 => {
                    tracing::debug!(error = %format!("{error:#}"), attempt, detour, "detour warm-up failed, retrying");
                    tokio::time::sleep(std::time::Duration::from_millis(300 * u64::from(attempt)))
                        .await;
                }
                Err(error) => {
                    tracing::warn!(error = %format!("{error:#}"), attempt, detour, "detour warm-up failed after 3 attempts");
                }
            }
        }
    }
    let remote_sets: Vec<_> = route
        .rule_set
        .iter()
        .filter(|set| set.r#type == "remote")
        .cloned()
        .collect();

    let tasks = remote_sets.into_iter().map(|set| {
        let tag = set.tag.clone();
        let url_opt = set.url.clone();
        let format_opt = set
            .url
            .as_deref()
            .and_then(|url| crate::routing::rule_set_format_for(&set, url).ok())
            .map(|s| s.to_owned());
        async move {
            let url = url_opt?;
            let format = format_opt?;
            let cache_path = crate::routing::rule_set_cache_path(&url, &format);
            let cached_etag = std::fs::read(cache_path.with_extension("etag"))
                .ok()
                .map(|bytes| String::from_utf8_lossy(&bytes).trim().to_owned())
                .filter(|value| !value.is_empty());
            match provider.fetch_url_etag(detour, &url, cached_etag.as_deref()).await {
                Ok((data, new_etag, not_modified)) => {
                    if not_modified {
                        tracing::debug!(tag = %tag, "remote rule-set not modified");
                        if let Ok(data) = std::fs::read(&cache_path) {
                            return Some((tag, data));
                        }
                        return None;
                    }
                    tracing::info!(
                        tag = %tag,
                        bytes = data.len(),
                        "prefetched remote rule-set through http_client"
                    );
                    if let Err(error) = crate::routing::write_rule_set_cache(&cache_path, &data) {
                        tracing::warn!(error = %format!("{error:#}"), tag = %tag, "failed to write rule-set cache");
                    }
                    if let Some(etag) = new_etag
                        && let Err(error) = std::fs::write(cache_path.with_extension("etag"), etag)
                    {
                        tracing::warn!(error = %format!("{error:#}"), tag = %tag, "failed to write rule-set etag");
                    }
                    Some((tag, data))
                }
                Err(error) => {
                    tracing::warn!(
                        error = %format!("{error:#}"),
                        tag = %tag,
                        "failed to prefetch remote rule-set through http_client; falling back to direct download"
                    );
                    None
                }
            }
        }
    });

    let results = futures_util::future::join_all(tasks).await;
    let mut prefetched = HashMap::new();
    for item in results.into_iter().flatten() {
        prefetched.insert(item.0, item.1);
    }
    prefetched
}

#[cfg(test)]
mod tests {
    use super::udp::{encode_socks_udp, parse_socks_udp, udp_response_proxy_destination};
    use super::*;
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
        let task = tokio::spawn(run_socks(
            inbound,
            vec![outbound],
            None,
            None,
            Vec::new(),
            None,
        ));
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
        let task = tokio::spawn(run_socks(
            inbound,
            outbounds,
            Some(route),
            None,
            Vec::new(),
            None,
        ));
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
        let task = tokio::spawn(run_socks(
            inbound,
            vec![outbound],
            None,
            None,
            Vec::new(),
            None,
        ));
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
        let proxy_task = tokio::spawn(run_socks(
            inbound,
            vec![outbound],
            None,
            None,
            Vec::new(),
            None,
        ));
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

    #[test]
    fn restored_selected_groups_switches_selector_selection() {
        let group = Arc::new(
            Group::new(
                GroupKind::Selector,
                vec!["node1".into(), "node2".into()],
                None,
                None,
                None,
                None,
            )
            .unwrap(),
        );
        assert_eq!(group.now(), "node1");

        let mut groups = HashMap::new();
        groups.insert("proxy".to_string(), group.clone());

        let mut selected_map = HashMap::new();
        selected_map.insert("proxy".to_string(), "node2".to_string());

        for (group_tag, member_tag) in selected_map {
            if let Some(group) = groups.get(&group_tag)
                && group.select(&member_tag)
            {
                // restored
            }
        }

        assert_eq!(group.now(), "node2");
    }
}

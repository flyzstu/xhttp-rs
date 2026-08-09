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
};
use anyhow::{Context, Result, bail};
use std::{
    collections::HashMap,
    net::ToSocketAddrs,
    sync::Arc,
};
use tokio::io::{AsyncRead, AsyncWrite};

pub(crate) use relay::{relay_anytls_tcp, relay_anytls_udp, relay_tun_tcp, relay_tun_udp};
pub use inbound::run_socks;
#[cfg(feature = "fuzzing")]
pub use udp::fuzz_socks_udp;
pub(crate) use crate::util::socket;
pub(crate) use crate::util::url_host;

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}
type BoxIo = Box<dyn Io>;
#[derive(Clone)]
enum Dialer {
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
}

#[derive(Clone)]
pub(crate) struct ProxyRuntime {
    dialers: Arc<HashMap<String, Dialer>>,
    router: Arc<Router>,
    resolver: Option<Arc<DnsResolver>>,
    tun_output_mark: Option<u32>,
}

pub(crate) async fn build_runtime(
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
    let mut first_tag = None;
    for outbound in outbounds {
        let tag = outbound
            .tag
            .clone()
            .unwrap_or_else(|| outbound.r#type.clone());
        let dialer = match outbound.r#type.as_str() {
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
    Ok(ProxyRuntime {
        dialers: Arc::new(dialers),
        router,
        resolver,
        tun_output_mark: None,
    })
}

impl ProxyRuntime {
    pub(crate) fn set_tun_output_mark(&mut self, mark: u32) {
        self.tun_output_mark = Some(mark);
    }

    pub(crate) fn rule_set_ip_cidrs(&self, tags: &[String]) -> Result<Vec<ipnet::IpNet>> {
        self.router.rule_set_ip_cidrs(tags)
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

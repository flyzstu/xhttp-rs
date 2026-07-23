use crate::{
    Client,
    config::{ClientConfig, ClientTlsConfig},
    dns::DnsResolver,
    linux_route::LinuxRouteMetadata,
    routing::{RouteContext, RouteDecision, RouteOptions, Router, RuleAction},
    singbox::{DnsConfig, Inbound, Outbound, RouteConfig, User},
    vless,
};
use anyhow::{Context, Result, bail};
use base64::Engine;
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    sync::Arc,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::mpsc,
};

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}
type BoxIo = Box<dyn Io>;
#[derive(Clone)]
enum Dialer {
    Direct,
    Block,
    Vless {
        client: Box<Client>,
        user: String,
        xudp: bool,
    },
}
pub async fn run_socks(
    inbound: Inbound,
    outbounds: Vec<Outbound>,
    route: Option<RouteConfig>,
    dns: Option<DnsConfig>,
) -> Result<()> {
    if !matches!(inbound.r#type.as_str(), "socks" | "http" | "mixed") {
        bail!("unsupported proxy inbound: {}", inbound.r#type)
    }
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
                let tls = outbound.tls.unwrap_or_default();
                let scheme = if tls.enabled { "https" } else { "http" };
                let server = outbound.server.context("VLESS outbound requires server")?;
                let port = outbound
                    .server_port
                    .unwrap_or(if tls.enabled { 443 } else { 80 });
                let url_name = if tls.enabled {
                    tls.server_name.as_deref().unwrap_or(&server)
                } else {
                    &server
                };
                let url = format!(
                    "{scheme}://{}:{}{}",
                    url_host(url_name),
                    port,
                    transport.path
                );
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
                    },
                })?;
                Dialer::Vless {
                    client: Box::new(client),
                    user: outbound.uuid.context("VLESS outbound requires uuid")?,
                    xudp: match outbound.packet_encoding.as_deref() {
                        None | Some("xudp") => true,
                        Some("") => false,
                        Some(value) => bail!("unsupported VLESS packet_encoding: {value}"),
                    },
                }
            }
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
    let route_config = route.unwrap_or_default();
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
    let resolver = dns
        .as_ref()
        .map(DnsResolver::new)
        .transpose()?
        .map(Arc::new);
    let listen = socket(
        inbound.listen.as_deref().unwrap_or("127.0.0.1"),
        inbound
            .listen_port
            .context("SOCKS inbound requires listen_port")?,
    );
    let listener = TcpListener::bind(&listen).await?;
    let dialers = Arc::new(dialers);
    let tag = Arc::new(inbound.tag.unwrap_or_else(|| "socks-in".into()));
    let protocol = Arc::new(inbound.r#type);
    let users = Arc::new(inbound.users);
    loop {
        let (stream, peer) = listener.accept().await?;
        let router = router.clone();
        let resolver = resolver.clone();
        let dialers = dialers.clone();
        let tag = tag.clone();
        let protocol = protocol.clone();
        let users = users.clone();
        tokio::spawn(async move {
            if let Err(error) = handle(
                stream,
                peer,
                HandleRuntime {
                    inbound: tag.as_str(),
                    protocol: protocol.as_str(),
                    users: &users,
                    router: &router,
                    resolver: resolver.as_deref(),
                    dialers: &dialers,
                },
            )
            .await
            {
                tracing::debug!(%error, %peer, "proxy connection closed");
            }
        });
    }
}

fn start_rule_set_updater(router: Arc<Router>, config: RouteConfig, default_outbound: String) {
    let update_interval = config
        .rule_set
        .iter()
        .filter(|set| set.r#type == "remote")
        .map(|set| {
            parse_duration(set.update_interval.as_deref().or(Some("24h")))
                .max(std::time::Duration::from_secs(60))
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
#[derive(Clone, Copy)]
struct HandleRuntime<'a> {
    inbound: &'a str,
    protocol: &'a str,
    users: &'a [User],
    router: &'a Router,
    resolver: Option<&'a DnsResolver>,
    dialers: &'a HashMap<String, Dialer>,
}

async fn handle(mut local: TcpStream, peer: SocketAddr, runtime: HandleRuntime<'_>) -> Result<()> {
    let HandleRuntime {
        inbound,
        protocol,
        users,
        router,
        resolver,
        dialers,
    } = runtime;
    let proxy_address = local.local_addr()?;
    let linux_metadata =
        tokio::task::spawn_blocking(move || crate::linux_route::collect_tcp(peer, proxy_address))
            .await
            .unwrap_or_default();
    let handshake = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        client_handshake(&mut local, protocol, users),
    )
    .await
    .context("proxy handshake timeout")??;
    let Handshake::Tcp {
        destination,
        reply,
        initial,
        auth_user,
    } = handshake
    else {
        if let Handshake::Udp { auth_user } = handshake {
            return udp_associate(
                local,
                peer,
                UdpAssociateRuntime {
                    inbound,
                    router,
                    resolver,
                    dialers,
                    linux_metadata,
                    auth_user,
                },
            )
            .await;
        }
        unreachable!()
    };
    let evaluation = evaluate_tcp_route(
        &local,
        &initial,
        destination,
        RouteInput {
            peer,
            inbound,
            router,
            resolver,
            linux: &linux_metadata,
            auth_user: auth_user.as_deref(),
        },
    )
    .await?;
    let RouteEvaluation {
        decision,
        destination,
        options: route_options,
    } = evaluation;
    if decision == RouteDecision::HijackDns {
        let resolver = resolver.context("DNS hijack requires a DNS configuration")?;
        if !initial.is_empty() {
            bail!("DNS hijack is only supported for SOCKS connections")
        }
        if let Some(reply) = &reply {
            local.write_all(reply).await?;
        }
        return relay_dns_tcp(&mut local, resolver).await;
    }
    let tag = match decision {
        RouteDecision::Outbound(v) => v,
        RouteDecision::Reject => {
            if route_options.reject_method.as_deref() == Some("reply") {
                if reply
                    .as_deref()
                    .is_some_and(|value| value.starts_with(b"HTTP/"))
                {
                    local
                        .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                        .await?;
                } else {
                    local.write_all(&[5, 2, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
                }
                return Ok(());
            }
            if !matches!(route_options.reject_method.as_deref(), Some("drop")) {
                reset_tcp_on_close(&local)?;
            }
            bail!("connection rejected")
        }
        RouteDecision::HijackDns => unreachable!(),
    };
    let dialer = dialers
        .get(&tag)
        .with_context(|| format!("unknown outbound: {tag}"))?;
    if matches!(dialer, Dialer::Block) {
        bail!("connection blocked by outbound")
    }
    if let Dialer::Vless { client, user, .. } = dialer {
        let mut remote = client.connect().await?;
        vless::write_request(&mut remote, user, &destination).await?;
        if !initial.is_empty() {
            remote.write_all(&initial).await?
        }
        if let Some(reply) = &reply {
            local.write_all(reply).await?
        }
        let (mut local_read, mut local_write) = local.split();
        let (mut remote_read, mut remote_write) = tokio::io::split(remote);
        tokio::try_join!(
            async {
                tokio::io::copy(&mut local_read, &mut remote_write).await?;
                remote_write.shutdown().await?;
                Ok::<(), anyhow::Error>(())
            },
            async {
                vless::read_response(&mut remote_read).await?;
                tokio::io::copy(&mut remote_read, &mut local_write).await?;
                local_write.shutdown().await?;
                Ok::<(), anyhow::Error>(())
            }
        )?;
    } else {
        let mut remote: BoxIo =
            Box::new(connect_direct(&destination, resolver, &route_options).await?);
        if let Some(reply) = &reply {
            local.write_all(reply).await?
        }
        if !initial.is_empty() {
            write_first_packet(&mut remote, &initial, &route_options).await?;
        } else if route_options.tls_fragment || route_options.tls_record_fragment {
            let mut first = vec![0; 16 * 1024];
            if let Ok(Ok(length)) = tokio::time::timeout(
                parse_duration(
                    route_options
                        .tls_fragment_fallback_delay
                        .as_deref()
                        .or(Some("500ms")),
                ),
                local.read(&mut first),
            )
            .await
            {
                if length == 0 {
                    return Ok(());
                }
                write_first_packet(&mut remote, &first[..length], &route_options).await?;
            }
        }
        tokio::io::copy_bidirectional(&mut local, &mut remote).await?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn reset_tcp_on_close(stream: &TcpStream) -> Result<()> {
    use std::os::fd::AsRawFd;
    let linger = libc::linger {
        l_onoff: 1,
        l_linger: 0,
    };
    let result = unsafe {
        libc::setsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_LINGER,
            (&linger as *const libc::linger).cast(),
            std::mem::size_of::<libc::linger>() as libc::socklen_t,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error()).context("set reject reset behavior");
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn reset_tcp_on_close(_stream: &TcpStream) -> Result<()> {
    Ok(())
}

async fn write_first_packet(
    remote: &mut BoxIo,
    packet: &[u8],
    options: &RouteOptions,
) -> Result<()> {
    let Some(server_name) = tls_server_name(packet) else {
        remote.write_all(packet).await?;
        return Ok(());
    };
    let Some(name_start) = packet
        .windows(server_name.len())
        .position(|window| window.eq_ignore_ascii_case(server_name.as_bytes()))
    else {
        remote.write_all(packet).await?;
        return Ok(());
    };
    let split = name_start + server_name.len().max(2) / 2;
    if options.tls_record_fragment && packet.len() >= 5 {
        let record_end =
            (5 + u16::from_be_bytes([packet[3], packet[4]]) as usize).min(packet.len());
        if split <= 5 || split >= record_end {
            remote.write_all(packet).await?;
            return Ok(());
        }
        for payload in [&packet[5..split], &packet[split..record_end]] {
            remote.write_all(&packet[..3]).await?;
            remote
                .write_u16(payload.len().try_into().context("TLS record too large")?)
                .await?;
            remote.write_all(payload).await?;
        }
        remote.write_all(&packet[record_end..]).await?;
    } else if options.tls_fragment {
        remote.write_all(&packet[..split]).await?;
        remote.flush().await?;
        tokio::time::sleep(
            options
                .tls_fragment_fallback_delay
                .as_deref()
                .map(|value| parse_duration(Some(value)))
                .unwrap_or_else(|| std::time::Duration::from_millis(10)),
        )
        .await;
        remote.write_all(&packet[split..]).await?;
    } else {
        remote.write_all(packet).await?;
    }
    Ok(())
}

struct RouteEvaluation {
    decision: RouteDecision,
    destination: vless::Destination,
    options: RouteOptions,
}

#[derive(Clone, Copy)]
struct RouteInput<'a> {
    peer: SocketAddr,
    inbound: &'a str,
    router: &'a Router,
    resolver: Option<&'a DnsResolver>,
    linux: &'a LinuxRouteMetadata,
    auth_user: Option<&'a str>,
}

async fn evaluate_tcp_route(
    local: &TcpStream,
    initial: &[u8],
    destination: vless::Destination,
    input: RouteInput<'_>,
) -> Result<RouteEvaluation> {
    let RouteInput {
        peer,
        inbound,
        router,
        resolver,
        linux,
        auth_user,
    } = input;
    let mut domain = match &destination {
        vless::Destination::Domain(value, _) => Some(value.clone()),
        vless::Destination::Ip(_, _) => None,
    };
    let mut destination_ip = match destination {
        vless::Destination::Ip(value, _) => Some(value),
        vless::Destination::Domain(_, _) => None,
    };
    if destination_ip.is_none()
        && let (Some(name), Some(resolver)) = (domain.as_deref(), resolver)
    {
        destination_ip = resolver
            .lookup(name)
            .await
            .ok()
            .and_then(|values| values.into_iter().next());
    }
    let mut detected_protocol = None;
    let mut detected_client = None;
    let clash_mode = std::env::var("XHTTP_CLASH_MODE").ok();
    let mut options = RouteOptions::default();
    let mut cursor = 0;
    let decision = loop {
        let context = RouteContext {
            domain: domain.as_deref(),
            destination_ip,
            destination_port: Some(destination.port()),
            source_ip: Some(peer.ip()),
            source_port: Some(peer.port()),
            network: Some("tcp"),
            protocol: detected_protocol.as_deref(),
            client: detected_client.as_deref(),
            inbound: Some(inbound),
            auth_user,
            process_name: linux.process_name.as_deref(),
            process_path: linux.process_path.as_deref(),
            user: linux.user.as_deref(),
            user_id: linux.user_id,
            clash_mode: clash_mode.as_deref(),
            network_type: linux.network_type.as_deref(),
            network_is_expensive: linux.network_is_expensive,
            network_is_constrained: linux.network_is_constrained,
            wifi_ssid: linux.wifi_ssid.as_deref(),
            wifi_bssid: linux.wifi_bssid.as_deref(),
            interface_addresses: Some(&linux.interface_addresses),
            network_interface_addresses: Some(&linux.network_interface_addresses),
            source_mac_address: linux.source_mac_address.as_deref(),
            source_hostname: linux.source_hostname.as_deref(),
            default_interface_addresses: &linux.default_interface_addresses,
            ..Default::default()
        };
        let Some((index, action)) = router.next_action(&context, cursor) else {
            break RouteDecision::Outbound(router.final_outbound().to_owned());
        };
        cursor = index + 1;
        match action {
            RuleAction::Route {
                decision,
                options: action_options,
            } => {
                options.merge(&action_options);
                break decision;
            }
            RuleAction::RouteOptions(action_options) => options.merge(&action_options),
            RuleAction::Resolve {
                server,
                timeout,
                strategy,
                disable_cache,
            } => {
                if let (Some(name), Some(resolver)) = (domain.as_deref(), resolver) {
                    destination_ip = select_address(
                        resolve_for_route(
                            resolver,
                            name,
                            server.as_deref(),
                            timeout.as_deref(),
                            disable_cache,
                        )
                        .await?,
                        strategy.as_deref(),
                    );
                }
            }
            RuleAction::Sniff { sniffers, timeout } => {
                let sniffed = sniff_tcp(
                    local,
                    initial,
                    &sniffers,
                    parse_duration(timeout.as_deref()),
                )
                .await;
                if let Some(sniffed) = sniffed {
                    detected_protocol = Some(sniffed.protocol);
                    detected_client = sniffed.client;
                    if sniffed.domain.is_some() {
                        domain = sniffed.domain;
                    }
                }
            }
        }
    };
    Ok(RouteEvaluation {
        decision,
        destination: override_destination(destination, &options)?,
        options,
    })
}

async fn evaluate_udp_route(
    destination: vless::Destination,
    payload: &[u8],
    input: RouteInput<'_>,
) -> Result<RouteEvaluation> {
    let RouteInput {
        peer,
        inbound,
        router,
        resolver,
        linux,
        auth_user,
    } = input;
    let mut domain = match &destination {
        vless::Destination::Domain(value, _) => Some(value.clone()),
        vless::Destination::Ip(_, _) => None,
    };
    let mut destination_ip = match &destination {
        vless::Destination::Ip(value, _) => Some(*value),
        vless::Destination::Domain(_, _) => None,
    };
    if destination_ip.is_none()
        && let (Some(name), Some(resolver)) = (domain.as_deref(), resolver)
    {
        destination_ip = resolver
            .lookup(name)
            .await
            .ok()
            .and_then(|values| values.into_iter().next());
    }
    let mut detected_protocol = None;
    let mut detected_client = None;
    let clash_mode = std::env::var("XHTTP_CLASH_MODE").ok();
    let mut options = RouteOptions::default();
    let mut cursor = 0;
    let decision = loop {
        let context = RouteContext {
            domain: domain.as_deref(),
            destination_ip,
            destination_port: Some(destination.port()),
            source_ip: Some(peer.ip()),
            source_port: Some(peer.port()),
            network: Some("udp"),
            protocol: detected_protocol.as_deref(),
            client: detected_client.as_deref(),
            inbound: Some(inbound),
            auth_user,
            process_name: linux.process_name.as_deref(),
            process_path: linux.process_path.as_deref(),
            user: linux.user.as_deref(),
            user_id: linux.user_id,
            clash_mode: clash_mode.as_deref(),
            network_type: linux.network_type.as_deref(),
            network_is_expensive: linux.network_is_expensive,
            network_is_constrained: linux.network_is_constrained,
            wifi_ssid: linux.wifi_ssid.as_deref(),
            wifi_bssid: linux.wifi_bssid.as_deref(),
            interface_addresses: Some(&linux.interface_addresses),
            network_interface_addresses: Some(&linux.network_interface_addresses),
            source_mac_address: linux.source_mac_address.as_deref(),
            source_hostname: linux.source_hostname.as_deref(),
            default_interface_addresses: &linux.default_interface_addresses,
            ..Default::default()
        };
        let Some((index, action)) = router.next_action(&context, cursor) else {
            break RouteDecision::Outbound(router.final_outbound().to_owned());
        };
        cursor = index + 1;
        match action {
            RuleAction::Route {
                decision,
                options: action_options,
            } => {
                options.merge(&action_options);
                break decision;
            }
            RuleAction::RouteOptions(action_options) => options.merge(&action_options),
            RuleAction::Resolve {
                server,
                timeout,
                strategy,
                disable_cache,
            } => {
                if let (Some(name), Some(resolver)) = (domain.as_deref(), resolver) {
                    destination_ip = select_address(
                        resolve_for_route(
                            resolver,
                            name,
                            server.as_deref(),
                            timeout.as_deref(),
                            disable_cache,
                        )
                        .await?,
                        strategy.as_deref(),
                    );
                }
            }
            RuleAction::Sniff {
                sniffers,
                timeout: _,
            } => {
                if let Some(sniffed) = sniff_payload(payload, true, &sniffers) {
                    detected_protocol = Some(sniffed.protocol);
                    detected_client = sniffed.client;
                    if sniffed.domain.is_some() {
                        domain = sniffed.domain;
                    }
                }
            }
        }
    };
    Ok(RouteEvaluation {
        decision,
        destination: override_destination(destination, &options)?,
        options,
    })
}

async fn resolve_for_route(
    resolver: &DnsResolver,
    name: &str,
    server: Option<&str>,
    timeout: Option<&str>,
    disable_cache: bool,
) -> Result<Vec<IpAddr>> {
    tokio::time::timeout(
        timeout
            .map(|value| parse_duration(Some(value)))
            .unwrap_or_else(|| std::time::Duration::from_secs(5)),
        resolver.lookup_with(name, server, disable_cache),
    )
    .await
    .context("route DNS resolution timeout")?
}

fn override_destination(
    original: vless::Destination,
    options: &RouteOptions,
) -> Result<vless::Destination> {
    let port = options.override_port.unwrap_or_else(|| original.port());
    let Some(host) = options.override_address.as_deref() else {
        return Ok(match original {
            vless::Destination::Ip(address, _) => vless::Destination::Ip(address, port),
            vless::Destination::Domain(domain, _) => vless::Destination::Domain(domain, port),
        });
    };
    Ok(match host.parse::<IpAddr>() {
        Ok(address) => vless::Destination::Ip(address, port),
        Err(_) => vless::Destination::Domain(host.to_owned(), port),
    })
}

fn select_address(addresses: Vec<IpAddr>, strategy: Option<&str>) -> Option<IpAddr> {
    match strategy.unwrap_or("") {
        "ipv4_only" => addresses.into_iter().find(IpAddr::is_ipv4),
        "ipv6_only" => addresses.into_iter().find(IpAddr::is_ipv6),
        "prefer_ipv4" => addresses
            .iter()
            .copied()
            .find(IpAddr::is_ipv4)
            .or_else(|| addresses.into_iter().next()),
        "prefer_ipv6" => addresses
            .iter()
            .copied()
            .find(IpAddr::is_ipv6)
            .or_else(|| addresses.into_iter().next()),
        _ => addresses.into_iter().next(),
    }
}

#[derive(Debug)]
struct SniffResult {
    protocol: String,
    domain: Option<String>,
    client: Option<String>,
}

async fn sniff_tcp(
    stream: &TcpStream,
    initial: &[u8],
    sniffers: &[String],
    duration: std::time::Duration,
) -> Option<SniffResult> {
    let mut peeked = vec![0; 8192];
    let data = if initial.is_empty() {
        let length = tokio::time::timeout(duration, stream.peek(&mut peeked))
            .await
            .ok()?
            .ok()?;
        &peeked[..length]
    } else {
        initial
    };
    sniff_payload(data, false, sniffers)
}

fn sniff_payload(data: &[u8], udp: bool, sniffers: &[String]) -> Option<SniffResult> {
    let enabled = |name: &str| sniffers.is_empty() || sniffers.iter().any(|item| item == name);
    if !udp && enabled("tls") && data.starts_with(&[0x16, 0x03]) {
        return Some(SniffResult {
            protocol: "tls".into(),
            domain: tls_server_name(data),
            client: None,
        });
    }
    if !udp
        && enabled("http")
        && [
            b"GET ", b"POST", b"HEAD", b"PUT ", b"OPTI", b"CONN", b"DELE", b"PATC",
        ]
        .iter()
        .any(|prefix| data.starts_with(*prefix))
    {
        let text = String::from_utf8_lossy(data);
        let domain = text.lines().find_map(|line| {
            line.split_once(':')
                .filter(|(name, _)| name.eq_ignore_ascii_case("host"))
                .and_then(|(_, value)| {
                    value
                        .trim()
                        .trim_matches(['[', ']'])
                        .split(':')
                        .next()
                        .map(str::to_owned)
                })
        });
        let client = text.lines().find_map(|line| {
            line.split_once(':')
                .filter(|(name, _)| name.eq_ignore_ascii_case("user-agent"))
                .map(|(_, value)| value.trim().to_owned())
        });
        return Some(SniffResult {
            protocol: "http".into(),
            domain,
            client,
        });
    }
    if !udp && enabled("ssh") && data.starts_with(b"SSH-") {
        return Some(SniffResult {
            protocol: "ssh".into(),
            domain: None,
            client: String::from_utf8_lossy(data)
                .lines()
                .next()
                .map(str::to_owned),
        });
    }
    if !udp && enabled("rdp") && data.len() >= 7 && data.starts_with(&[3, 0]) && data[5] == 0xe0 {
        return Some(SniffResult {
            protocol: "rdp".into(),
            domain: None,
            client: None,
        });
    }
    if enabled("dns") && is_dns_message(data, !udp) {
        return Some(SniffResult {
            protocol: "dns".into(),
            domain: dns_question_name(data, !udp),
            client: None,
        });
    }
    if udp && enabled("stun") && data.get(4..8) == Some(&[0x21, 0x12, 0xa4, 0x42]) {
        return Some(SniffResult {
            protocol: "stun".into(),
            domain: None,
            client: None,
        });
    }
    if udp && enabled("quic") && data.first().is_some_and(|value| value & 0x80 != 0) {
        return Some(SniffResult {
            protocol: "quic".into(),
            domain: None,
            client: None,
        });
    }
    if udp
        && enabled("dtls")
        && data.len() >= 13
        && matches!(data[0], 20..=64)
        && data[1] == 0xfe
        && matches!(data[2], 0xfd | 0xff)
    {
        return Some(SniffResult {
            protocol: "dtls".into(),
            domain: None,
            client: None,
        });
    }
    if udp
        && enabled("ntp")
        && data.len() >= 48
        && matches!(data[0] & 0x07, 1..=5)
        && data[0] >> 6 != 3
    {
        return Some(SniffResult {
            protocol: "ntp".into(),
            domain: None,
            client: None,
        });
    }
    if udp && enabled("utp") && data.len() >= 20 && data[0] & 0x0f == 1 && data[0] >> 4 <= 4 {
        return Some(SniffResult {
            protocol: "utp".into(),
            domain: None,
            client: None,
        });
    }
    if udp
        && enabled("udp_tracker")
        && data.len() >= 16
        && data.starts_with(&[0, 0, 4, 23, 39, 16, 25, 128])
    {
        return Some(SniffResult {
            protocol: "udp_tracker".into(),
            domain: None,
            client: None,
        });
    }
    if !udp && enabled("bittorrent") && data.starts_with(b"\x13BitTorrent protocol") {
        return Some(SniffResult {
            protocol: "bittorrent".into(),
            domain: None,
            client: None,
        });
    }
    None
}

fn parse_duration(value: Option<&str>) -> std::time::Duration {
    let Some(value) = value else {
        return std::time::Duration::from_millis(300);
    };
    if let Some(milliseconds) = value.strip_suffix("ms").and_then(|v| v.parse().ok()) {
        std::time::Duration::from_millis(milliseconds)
    } else if let Some(seconds) = value.strip_suffix('s').and_then(|v| v.parse().ok()) {
        std::time::Duration::from_secs(seconds)
    } else if let Some(minutes) = value.strip_suffix('m').and_then(|v| v.parse::<u64>().ok()) {
        std::time::Duration::from_secs(minutes.saturating_mul(60))
    } else if let Some(hours) = value.strip_suffix('h').and_then(|v| v.parse::<u64>().ok()) {
        std::time::Duration::from_secs(hours.saturating_mul(60 * 60))
    } else {
        std::time::Duration::from_millis(300)
    }
}

fn is_dns_message(data: &[u8], tcp: bool) -> bool {
    let data = if tcp {
        let Some(length) = data
            .get(..2)
            .map(|value| u16::from_be_bytes([value[0], value[1]]) as usize)
        else {
            return false;
        };
        let Some(message) = data.get(2..2 + length) else {
            return false;
        };
        message
    } else {
        data
    };
    data.len() >= 12 && data[2] & 0x80 == 0 && u16::from_be_bytes([data[4], data[5]]) > 0
}

fn dns_question_name(data: &[u8], tcp: bool) -> Option<String> {
    let data = if tcp { data.get(2..)? } else { data };
    let mut position = 12;
    let mut labels = Vec::new();
    loop {
        let length = *data.get(position)? as usize;
        position += 1;
        if length == 0 {
            break;
        }
        if length > 63 {
            return None;
        }
        labels.push(std::str::from_utf8(data.get(position..position + length)?).ok()?);
        position += length;
    }
    Some(labels.join(".").to_ascii_lowercase())
}

fn tls_server_name(data: &[u8]) -> Option<String> {
    if data.len() < 5 {
        return None;
    }
    let record_length = u16::from_be_bytes([data[3], data[4]]) as usize;
    let handshake = data.get(5..5 + record_length)?;
    if handshake.first() != Some(&1) || handshake.len() < 42 {
        return None;
    }
    let mut position = 4 + 2 + 32;
    position += 1 + *handshake.get(position)? as usize;
    let suites =
        u16::from_be_bytes([*handshake.get(position)?, *handshake.get(position + 1)?]) as usize;
    position += 2 + suites;
    position += 1 + *handshake.get(position)? as usize;
    let extensions_length =
        u16::from_be_bytes([*handshake.get(position)?, *handshake.get(position + 1)?]) as usize;
    position += 2;
    let end = position
        .checked_add(extensions_length)?
        .min(handshake.len());
    while position + 4 <= end {
        let kind = u16::from_be_bytes([handshake[position], handshake[position + 1]]);
        let length =
            u16::from_be_bytes([handshake[position + 2], handshake[position + 3]]) as usize;
        position += 4;
        let extension = handshake.get(position..position + length)?;
        if kind == 0 && extension.len() >= 5 {
            let name_length = u16::from_be_bytes([extension[3], extension[4]]) as usize;
            return Some(
                std::str::from_utf8(extension.get(5..5 + name_length)?)
                    .ok()?
                    .to_ascii_lowercase(),
            );
        }
        position += length;
    }
    None
}

enum Handshake {
    Tcp {
        destination: vless::Destination,
        reply: Option<Vec<u8>>,
        initial: Vec<u8>,
        auth_user: Option<String>,
    },
    Udp {
        auth_user: Option<String>,
    },
}
async fn client_handshake(
    stream: &mut TcpStream,
    protocol: &str,
    users: &[User],
) -> Result<Handshake> {
    let selected = if protocol == "mixed" {
        let mut b = [0];
        stream.peek(&mut b).await?;
        if b[0] == 5 { "socks" } else { "http" }
    } else {
        protocol
    };
    match selected {
        "socks" => {
            let (command, destination, auth_user) = socks_handshake(stream, users).await?;
            match command {
                1 => Ok(Handshake::Tcp {
                    destination,
                    reply: Some(vec![5, 0, 0, 1, 0, 0, 0, 0, 0, 0]),
                    initial: vec![],
                    auth_user,
                }),
                3 => Ok(Handshake::Udp { auth_user }),
                _ => bail!("unsupported SOCKS command"),
            }
        }
        "http" => http_handshake(stream, users).await,
        _ => bail!("unsupported inbound protocol"),
    }
}
async fn http_handshake(stream: &mut TcpStream, users: &[User]) -> Result<Handshake> {
    let mut request = Vec::new();
    let mut byte = [0];
    while request.len() < 16 * 1024 {
        stream.read_exact(&mut byte).await?;
        request.push(byte[0]);
        if request.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    if !request.ends_with(b"\r\n\r\n") {
        bail!("HTTP proxy header too large")
    };
    let text = std::str::from_utf8(&request)?;
    let auth_user = if users.is_empty() {
        None
    } else {
        let credentials = text
            .lines()
            .find_map(|line| {
                line.split_once(':').and_then(|(name, value)| {
                    name.eq_ignore_ascii_case("proxy-authorization")
                        .then(|| value.trim())
                })
            })
            .and_then(|value| value.split_once(' '))
            .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("basic"))
            .and_then(|(_, encoded)| {
                base64::engine::general_purpose::STANDARD
                    .decode(encoded)
                    .ok()
            })
            .and_then(|value| String::from_utf8(value).ok());
        let authenticated = credentials
            .as_deref()
            .and_then(|value| value.split_once(':'))
            .filter(|(name, password)| authenticate(users, name, password).is_ok());
        let Some((name, _)) = authenticated else {
            stream
                .write_all(
                    b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"xhttp-rs\"\r\nContent-Length: 0\r\n\r\n",
                )
                .await?;
            bail!("HTTP proxy authentication required")
        };
        Some(name.to_owned())
    };
    let line = text.lines().next().context("missing HTTP request line")?;
    let mut parts = line.split_whitespace();
    let method = parts.next().context("missing HTTP method")?;
    let target = parts.next().context("missing HTTP target")?;
    let version = parts.next().context("missing HTTP version")?;
    if method.eq_ignore_ascii_case("CONNECT") {
        let authority: axum::http::uri::Authority = target.parse()?;
        let port = authority.port_u16().unwrap_or(443);
        return Ok(Handshake::Tcp {
            destination: vless::parse_destination(authority.host(), port),
            reply: Some(b"HTTP/1.1 200 Connection Established\r\n\r\n".to_vec()),
            initial: vec![],
            auth_user,
        });
    }
    let url = url::Url::parse(target).context("HTTP proxy request requires absolute URI")?;
    let host = url.host_str().context("HTTP target has no host")?;
    let port = url
        .port_or_known_default()
        .context("HTTP target has no port")?;
    let path = match url.query() {
        Some(q) => format!("{}?{q}", url.path()),
        None => url.path().to_owned(),
    };
    let mut initial = format!("{method} {path} {version}\r\n").into_bytes();
    for header in text.lines().skip(1).take_while(|line| !line.is_empty()) {
        let name = header.split_once(':').map(|(name, _)| name).unwrap_or("");
        if name.eq_ignore_ascii_case("proxy-authorization")
            || name.eq_ignore_ascii_case("proxy-connection")
        {
            continue;
        }
        initial.extend_from_slice(header.as_bytes());
        initial.extend_from_slice(b"\r\n");
    }
    initial.extend_from_slice(b"\r\n");
    Ok(Handshake::Tcp {
        destination: vless::parse_destination(host, port),
        reply: None,
        initial,
        auth_user,
    })
}
async fn socks_handshake(
    stream: &mut TcpStream,
    users: &[User],
) -> Result<(u8, vless::Destination, Option<String>)> {
    if stream.read_u8().await? != 5 {
        bail!("unsupported SOCKS version")
    };
    let n = stream.read_u8().await? as usize;
    let mut methods = vec![0; n];
    stream.read_exact(&mut methods).await?;
    let method = if users.is_empty() { 0 } else { 2 };
    if !methods.contains(&method) {
        stream.write_all(&[5, 0xff]).await?;
        bail!("SOCKS authentication method unavailable")
    };
    stream.write_all(&[5, method]).await?;
    let auth_user = if method == 2 {
        if stream.read_u8().await? != 1 {
            bail!("unsupported SOCKS authentication version")
        }
        let name_length = stream.read_u8().await? as usize;
        let mut name = vec![0; name_length];
        stream.read_exact(&mut name).await?;
        let password_length = stream.read_u8().await? as usize;
        let mut password = vec![0; password_length];
        stream.read_exact(&mut password).await?;
        let name = String::from_utf8(name)?;
        let password = String::from_utf8(password)?;
        if authenticate(users, &name, &password).is_err() {
            stream.write_all(&[1, 1]).await?;
            bail!("invalid SOCKS credentials")
        }
        stream.write_all(&[1, 0]).await?;
        Some(name)
    } else {
        None
    };
    if stream.read_u8().await? != 5 {
        bail!("unsupported SOCKS request version")
    };
    let command = stream.read_u8().await?;
    if !matches!(command, 1 | 3) {
        bail!("only SOCKS CONNECT and UDP ASSOCIATE are supported")
    }
    let _ = stream.read_u8().await?;
    let address = match stream.read_u8().await? {
        1 => {
            let mut b = [0; 4];
            stream.read_exact(&mut b).await?;
            vless::Destination::Ip(IpAddr::from(b), stream.read_u16().await?)
        }
        3 => {
            let n = stream.read_u8().await? as usize;
            let mut b = vec![0; n];
            stream.read_exact(&mut b).await?;
            let host = String::from_utf8(b)?;
            vless::Destination::Domain(host, stream.read_u16().await?)
        }
        4 => {
            let mut b = [0; 16];
            stream.read_exact(&mut b).await?;
            vless::Destination::Ip(IpAddr::from(b), stream.read_u16().await?)
        }
        _ => bail!("invalid SOCKS address"),
    };
    Ok((command, address, auth_user))
}

fn authenticate(users: &[User], name: &str, password: &str) -> Result<()> {
    users
        .iter()
        .any(|user| {
            user.name.as_deref() == Some(name) && user.password.as_deref() == Some(password)
        })
        .then_some(())
        .context("invalid proxy credentials")
}

struct UdpAssociateRuntime<'a> {
    inbound: &'a str,
    router: &'a Router,
    resolver: Option<&'a DnsResolver>,
    dialers: &'a HashMap<String, Dialer>,
    linux_metadata: LinuxRouteMetadata,
    auth_user: Option<String>,
}

async fn udp_associate(
    mut control: TcpStream,
    tcp_peer: SocketAddr,
    runtime: UdpAssociateRuntime<'_>,
) -> Result<()> {
    let UdpAssociateRuntime {
        inbound,
        router,
        resolver,
        dialers,
        linux_metadata,
        auth_user,
    } = runtime;
    let local_ip = control.local_addr()?.ip();
    let socket = Arc::new(
        UdpSocket::bind(SocketAddr::new(local_ip, 0))
            .await
            .context("bind SOCKS UDP relay")?,
    );
    control
        .write_all(&socks_reply(socket.local_addr()?))
        .await?;
    let mut buffer = vec![0; u16::MAX as usize + 262];
    let mut sessions: HashMap<String, mpsc::Sender<Vec<u8>>> = HashMap::new();
    loop {
        tokio::select! {
            read = control.read_u8() => match read {
                Ok(_) => continue,
                Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
                Err(error) => return Err(error.into()),
            },
            received = socket.recv_from(&mut buffer) => {
                let (length, peer) = received?;
                if peer.ip() != tcp_peer.ip() {
                    continue;
                }
                let (destination, payload) = match parse_socks_udp(&buffer[..length]) {
                    Ok(value) => value,
                    Err(error) => {
                        tracing::debug!(%error, %peer, "discarding invalid SOCKS UDP datagram");
                        continue;
                    }
                };
                let evaluation = evaluate_udp_route(
                    destination,
                    payload,
                    RouteInput {
                        peer: tcp_peer,
                        inbound,
                        router,
                        resolver,
                        linux: &linux_metadata,
                        auth_user: auth_user.as_deref(),
                    },
                )
                .await?;
                let RouteEvaluation {
                    decision,
                    destination,
                    options,
                } = evaluation;
                let tag = match decision {
                    RouteDecision::Outbound(value) => value,
                    RouteDecision::Reject => continue,
                    RouteDecision::HijackDns => {
                        let Some(resolver) = resolver.cloned() else {
                            tracing::warn!("DNS hijack requires a DNS configuration");
                            continue;
                        };
                        let socket = socket.clone();
                        let destination = destination.clone();
                        let request = payload.to_vec();
                        tokio::spawn(async move {
                            match resolver.exchange(&request).await {
                                Ok(response) => {
                                    if let Ok(packet) = encode_socks_udp(&destination, &response) {
                                        let _ = socket.send_to(&packet, peer).await;
                                    }
                                }
                                Err(error) => tracing::debug!(%error, "hijacked UDP DNS query failed"),
                            }
                        });
                        continue;
                    }
                };
                let Some(dialer) = dialers.get(&tag).cloned() else {
                    tracing::warn!(outbound = %tag, "UDP route selected an unknown outbound");
                    continue;
                };
                if matches!(dialer, Dialer::Block) {
                    continue;
                }
                let key = format!("{tag}|{}:{}", destination.host(), destination.port());
                let sender = if let Some(sender) = sessions.get(&key).filter(|value| !value.is_closed()) {
                    sender.clone()
                } else {
                    let (sender, receiver) = mpsc::channel(64);
                    sessions.insert(key, sender.clone());
                    let socket = socket.clone();
                    let resolver = resolver.cloned();
                    tokio::spawn(async move {
                        if let Err(error) = udp_session(socket, peer, destination, dialer, resolver, options, receiver).await {
                            tracing::debug!(%error, "SOCKS UDP session closed");
                        }
                    });
                    sender
                };
                if sender.send(payload.to_vec()).await.is_err() {
                    sessions.retain(|_, value| !value.is_closed());
                }
            }
        }
    }
}

async fn relay_dns_tcp(stream: &mut TcpStream, resolver: &DnsResolver) -> Result<()> {
    loop {
        let length = match stream.read_u16().await {
            Ok(value) => value as usize,
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        let mut request = vec![0; length];
        stream.read_exact(&mut request).await?;
        let response = resolver.exchange(&request).await?;
        stream
            .write_u16(
                response
                    .len()
                    .try_into()
                    .context("DNS response too large")?,
            )
            .await?;
        stream.write_all(&response).await?;
        stream.flush().await?;
    }
}

async fn udp_session(
    relay: Arc<UdpSocket>,
    client: SocketAddr,
    destination: vless::Destination,
    dialer: Dialer,
    resolver: Option<DnsResolver>,
    options: RouteOptions,
    mut packets: mpsc::Receiver<Vec<u8>>,
) -> Result<()> {
    let idle_timeout = options
        .udp_timeout
        .as_deref()
        .map(|value| parse_duration(Some(value)))
        .unwrap_or_else(|| std::time::Duration::from_secs(120));
    match dialer {
        Dialer::Direct => {
            let target = resolve_udp(&destination, resolver.as_ref()).await?;
            let socket = direct_udp_socket(target, &options)?;
            if options.udp_connect {
                socket.connect(target).await?;
            }
            let mut response = vec![0; u16::MAX as usize];
            loop {
                let event = tokio::time::timeout(idle_timeout, async {
                    tokio::select! {
                        packet = packets.recv() => Ok::<_, anyhow::Error>((packet, None)),
                        received = async {
                            if options.udp_connect {
                                socket.recv(&mut response).await
                            } else {
                                socket.recv_from(&mut response).await.map(|(length, _)| length)
                            }
                        } => Ok((None, Some(received?))),
                    }
                })
                .await
                .context("UDP session idle timeout")??;
                match event {
                    (Some(packet), None) => {
                        if options.udp_connect {
                            socket.send(&packet).await?;
                        } else {
                            socket.send_to(&packet, target).await?;
                        }
                    }
                    (None, Some(length)) => {
                        relay
                            .send_to(
                                &encode_socks_udp(&destination, &response[..length])?,
                                client,
                            )
                            .await?;
                    }
                    (None, None) => return Ok(()),
                    _ => unreachable!(),
                }
            }
        }
        Dialer::Vless {
            client: xhttp,
            user,
            xudp,
        } => {
            let mut stream = xhttp.connect().await?;
            vless::write_request_with_command(
                &mut stream,
                &user,
                if xudp {
                    vless::Command::Xudp
                } else {
                    vless::Command::Udp
                },
                &destination,
            )
            .await?;
            let (mut read, mut write) = tokio::io::split(stream);
            let mut response_read = false;
            let mut first_xudp_packet = true;
            let mut response = vec![0; u16::MAX as usize];
            loop {
                let event = tokio::time::timeout(idle_timeout, async {
                    tokio::select! {
                        packet = packets.recv() => Ok::<_, anyhow::Error>((packet, None)),
                        received = async {
                            if !response_read {
                                vless::read_response(&mut read).await?;
                                response_read = true;
                            }
                            if xudp {
                                let (source, payload) = vless::read_xudp_packet(&mut read).await?;
                                Ok::<_, anyhow::Error>((source, payload))
                            } else {
                                let length = read.read_u16().await? as usize;
                                read.read_exact(&mut response[..length]).await?;
                                Ok((None, response[..length].to_vec()))
                            }
                        } => Ok((None, Some(received?))),
                    }
                })
                .await
                .context("VLESS UDP session idle timeout")??;
                match event {
                    (Some(packet), None) => {
                        if xudp {
                            vless::write_xudp_packet(
                                &mut write,
                                first_xudp_packet,
                                &destination,
                                &packet,
                            )
                            .await?;
                            first_xudp_packet = false;
                        } else {
                            write
                                .write_u16(packet.len().try_into().context("UDP packet too large")?)
                                .await?;
                            write.write_all(&packet).await?;
                            write.flush().await?;
                        }
                    }
                    (None, Some((source, payload))) => {
                        let source = source.as_ref().unwrap_or(&destination);
                        relay
                            .send_to(&encode_socks_udp(source, &payload)?, client)
                            .await?;
                    }
                    (None, None) => return Ok(()),
                    _ => unreachable!(),
                }
            }
        }
        Dialer::Block => Ok(()),
    }
}

async fn resolve_udp(
    destination: &vless::Destination,
    resolver: Option<&DnsResolver>,
) -> Result<SocketAddr> {
    match destination {
        vless::Destination::Ip(ip, port) => Ok(SocketAddr::new(*ip, *port)),
        vless::Destination::Domain(host, port) => {
            if let Some(resolver) = resolver {
                resolver
                    .lookup(host)
                    .await?
                    .into_iter()
                    .map(|ip| SocketAddr::new(ip, *port))
                    .next()
                    .context("DNS returned no UDP address")
            } else {
                tokio::net::lookup_host((host.as_str(), *port))
                    .await?
                    .next()
                    .context("UDP destination did not resolve")
            }
        }
    }
}

fn parse_socks_udp(packet: &[u8]) -> Result<(vless::Destination, &[u8])> {
    if packet.len() < 4 || packet[..2] != [0, 0] {
        bail!("invalid SOCKS UDP reserved field")
    }
    if packet[2] != 0 {
        bail!("fragmented SOCKS UDP datagrams are unsupported")
    }
    let (destination, offset) = decode_address(packet, 3)?;
    Ok((destination, &packet[offset..]))
}

#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub fn fuzz_socks_udp(packet: &[u8]) {
    let _ = parse_socks_udp(packet);
}

fn decode_address(packet: &[u8], offset: usize) -> Result<(vless::Destination, usize)> {
    let atyp = *packet.get(offset).context("missing SOCKS address type")?;
    let mut position = offset + 1;
    let host = match atyp {
        1 => {
            let bytes: [u8; 4] = packet
                .get(position..position + 4)
                .context("truncated IPv4 address")?
                .try_into()?;
            position += 4;
            std::net::IpAddr::from(bytes).to_string()
        }
        3 => {
            let length = *packet.get(position).context("missing domain length")? as usize;
            position += 1;
            let value = std::str::from_utf8(
                packet
                    .get(position..position + length)
                    .context("truncated domain")?,
            )?
            .to_owned();
            position += length;
            value
        }
        4 => {
            let bytes: [u8; 16] = packet
                .get(position..position + 16)
                .context("truncated IPv6 address")?
                .try_into()?;
            position += 16;
            std::net::IpAddr::from(bytes).to_string()
        }
        _ => bail!("invalid SOCKS address type"),
    };
    let port_bytes: [u8; 2] = packet
        .get(position..position + 2)
        .context("missing SOCKS port")?
        .try_into()?;
    position += 2;
    Ok((
        vless::parse_destination(&host, u16::from_be_bytes(port_bytes)),
        position,
    ))
}

fn encode_socks_udp(destination: &vless::Destination, payload: &[u8]) -> Result<Vec<u8>> {
    let mut packet = vec![0, 0, 0];
    encode_address(&mut packet, destination)?;
    packet.extend_from_slice(payload);
    Ok(packet)
}

fn socks_reply(address: SocketAddr) -> Vec<u8> {
    let mut reply = vec![5, 0, 0];
    encode_address(
        &mut reply,
        &vless::Destination::Ip(address.ip(), address.port()),
    )
    .expect("socket address is encodable");
    reply
}

fn encode_address(output: &mut Vec<u8>, destination: &vless::Destination) -> Result<()> {
    match destination {
        vless::Destination::Ip(IpAddr::V4(ip), port) => {
            output.push(1);
            output.extend_from_slice(&ip.octets());
            output.extend_from_slice(&port.to_be_bytes());
        }
        vless::Destination::Domain(host, port) => {
            let length: u8 = host.len().try_into().context("SOCKS domain is too long")?;
            output.extend([3, length]);
            output.extend_from_slice(host.as_bytes());
            output.extend_from_slice(&port.to_be_bytes());
        }
        vless::Destination::Ip(IpAddr::V6(ip), port) => {
            output.push(4);
            output.extend_from_slice(&ip.octets());
            output.extend_from_slice(&port.to_be_bytes());
        }
    }
    Ok(())
}
async fn connect_direct(
    destination: &vless::Destination,
    resolver: Option<&DnsResolver>,
    options: &RouteOptions,
) -> Result<TcpStream> {
    let timeout_duration = options
        .connect_timeout
        .as_deref()
        .map(|value| parse_duration(Some(value)))
        .unwrap_or(std::time::Duration::from_secs(10));
    let mut addresses = match destination {
        vless::Destination::Ip(ip, port) => vec![SocketAddr::new(*ip, *port)],
        vless::Destination::Domain(host, p) => {
            if let Some(r) = resolver {
                r.lookup(host)
                    .await?
                    .into_iter()
                    .map(|address| SocketAddr::new(address, *p))
                    .collect()
            } else {
                tokio::net::lookup_host((host.as_str(), *p))
                    .await?
                    .collect()
            }
        }
    };
    order_addresses(
        &mut addresses,
        options
            .domain_strategy
            .as_deref()
            .or(options.network_strategy.as_deref()),
    );
    for address in addresses {
        let socket = if address.is_ipv4() {
            tokio::net::TcpSocket::new_v4()?
        } else {
            tokio::net::TcpSocket::new_v6()?
        };
        socket.set_reuseaddr(options.reuse_addr)?;
        if let Some(bind) = if address.is_ipv4() {
            options.inet4_bind_address.as_deref()
        } else {
            options.inet6_bind_address.as_deref()
        } {
            socket.bind(SocketAddr::new(bind.parse()?, 0))?;
        }
        set_linux_socket_options(&socket, options)?;
        if let Ok(Ok(stream)) =
            tokio::time::timeout(timeout_duration, socket.connect(address)).await
        {
            return Ok(stream);
        }
    }
    bail!("all direct connection attempts failed")
}

fn order_addresses(addresses: &mut Vec<SocketAddr>, strategy: Option<&str>) {
    match strategy.unwrap_or("") {
        "ipv4_only" => addresses.retain(SocketAddr::is_ipv4),
        "ipv6_only" => addresses.retain(SocketAddr::is_ipv6),
        "prefer_ipv4" => addresses.sort_by_key(|address| !address.is_ipv4()),
        "prefer_ipv6" => addresses.sort_by_key(SocketAddr::is_ipv4),
        _ => {}
    }
}

fn direct_udp_socket(target: SocketAddr, options: &RouteOptions) -> Result<UdpSocket> {
    let configured = if target.is_ipv4() {
        options.inet4_bind_address.as_deref()
    } else {
        options.inet6_bind_address.as_deref()
    };
    let bind_ip = configured
        .map(str::parse)
        .transpose()
        .context("invalid UDP bind address")?
        .unwrap_or(if target.is_ipv4() {
            IpAddr::from([0, 0, 0, 0])
        } else {
            IpAddr::from([0u16; 8])
        });
    if bind_ip.is_ipv4() != target.is_ipv4() {
        bail!("UDP bind address family does not match destination")
    }
    let socket = std::net::UdpSocket::bind(SocketAddr::new(bind_ip, 0))?;
    socket.set_nonblocking(true)?;
    set_linux_udp_socket_options(&socket, options)?;
    UdpSocket::from_std(socket).context("create asynchronous UDP socket")
}

#[cfg(target_os = "linux")]
fn set_linux_udp_socket_options(
    socket: &std::net::UdpSocket,
    options: &RouteOptions,
) -> Result<()> {
    use std::{ffi::CString, os::fd::AsRawFd};
    let descriptor = socket.as_raw_fd();
    let set = |level, name, value: &libc::c_int, operation: &str| -> Result<()> {
        let result = unsafe {
            libc::setsockopt(
                descriptor,
                level,
                name,
                (value as *const libc::c_int).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if result != 0 {
            return Err(std::io::Error::last_os_error()).context(operation.to_owned());
        }
        Ok(())
    };
    if options.reuse_addr {
        set(
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            &1,
            "enable UDP address reuse",
        )?;
    }
    if let Some(interface) = &options.bind_interface {
        let interface = CString::new(interface.as_str()).context("invalid bind_interface")?;
        let result = unsafe {
            libc::setsockopt(
                descriptor,
                libc::SOL_SOCKET,
                libc::SO_BINDTODEVICE,
                interface.as_ptr().cast(),
                interface.as_bytes_with_nul().len() as libc::socklen_t,
            )
        };
        if result != 0 {
            return Err(std::io::Error::last_os_error()).context("bind UDP socket to interface");
        }
    }
    if let Some(mark) = options.routing_mark {
        let mark = mark as libc::c_int;
        set(
            libc::SOL_SOCKET,
            libc::SO_MARK,
            &mark,
            "set UDP socket mark",
        )?;
    }
    if let Some(fragment) = options.udp_fragment {
        let discovery = if fragment {
            libc::IP_PMTUDISC_WANT
        } else {
            libc::IP_PMTUDISC_DO
        };
        set(
            libc::IPPROTO_IP,
            libc::IP_MTU_DISCOVER,
            &discovery,
            "configure UDP fragmentation",
        )?;
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn set_linux_udp_socket_options(
    _socket: &std::net::UdpSocket,
    options: &RouteOptions,
) -> Result<()> {
    if options.bind_interface.is_some()
        || options.routing_mark.is_some()
        || options.udp_fragment.is_some()
    {
        bail!("Linux UDP socket options are unavailable on this platform")
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn set_linux_socket_options(socket: &tokio::net::TcpSocket, options: &RouteOptions) -> Result<()> {
    use std::{ffi::CString, os::fd::AsRawFd};
    let descriptor = socket.as_raw_fd();
    if let Some(interface) = &options.bind_interface {
        let interface = CString::new(interface.as_str()).context("invalid bind_interface")?;
        let result = unsafe {
            libc::setsockopt(
                descriptor,
                libc::SOL_SOCKET,
                libc::SO_BINDTODEVICE,
                interface.as_ptr().cast(),
                interface.as_bytes_with_nul().len() as libc::socklen_t,
            )
        };
        if result != 0 {
            return Err(std::io::Error::last_os_error()).context("bind socket to interface");
        }
    }
    if let Some(mark) = options.routing_mark {
        let result = unsafe {
            libc::setsockopt(
                descriptor,
                libc::SOL_SOCKET,
                libc::SO_MARK,
                (&mark as *const u32).cast(),
                std::mem::size_of::<u32>() as libc::socklen_t,
            )
        };
        if result != 0 {
            return Err(std::io::Error::last_os_error()).context("set socket routing mark");
        }
    }
    if options.tcp_fast_open {
        let enabled: libc::c_int = 1;
        let result = unsafe {
            libc::setsockopt(
                descriptor,
                libc::IPPROTO_TCP,
                libc::TCP_FASTOPEN_CONNECT,
                (&enabled as *const libc::c_int).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if result != 0 {
            return Err(std::io::Error::last_os_error()).context("enable TCP Fast Open");
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn set_linux_socket_options(_socket: &tokio::net::TcpSocket, options: &RouteOptions) -> Result<()> {
    if options.bind_interface.is_some() || options.routing_mark.is_some() || options.tcp_fast_open {
        bail!("Linux direct socket options are unavailable on this platform")
    }
    Ok(())
}
fn socket(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}
fn url_host(host: &str) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Server;
    use crate::config::{Mode, ServerConfig, TransportConfig};
    use crate::singbox::XHttpTransport;
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

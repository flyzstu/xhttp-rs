use crate::{
    dns::DnsResolver,
    linux_route::LinuxRouteMetadata,
    routing::{RouteContext, RouteDecision, RouteOptions, Router, RuleAction},
    vless,
};
use anyhow::{Context, Result};
use std::net::{IpAddr, SocketAddr};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    net::TcpStream,
};

use super::parse_duration;

pub(super) struct RouteEvaluation {
    pub(super) decision: RouteDecision,
    pub(super) destination: vless::Destination,
    pub(super) options: RouteOptions,
}
#[derive(Clone, Copy)]
pub(super) struct RouteInput<'a> {
    pub(super) peer: SocketAddr,
    pub(super) inbound: &'a str,
    pub(super) router: &'a Router,
    pub(super) resolver: Option<&'a DnsResolver>,
    pub(super) linux: &'a LinuxRouteMetadata,
    pub(super) auth_user: Option<&'a str>,
}
pub(super) async fn evaluate_tcp_route(
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
    let mut options = router.default_options();
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
                rewrite_ttl,
                client_subnet,
            } => {
                if let (Some(name), Some(resolver)) = (domain.as_deref(), resolver) {
                    destination_ip = select_address(
                        resolve_for_route(
                            resolver,
                            name,
                            crate::dns::LookupOptions {
                                server: server.as_deref(),
                                disable_cache,
                                rewrite_ttl,
                                timeout: timeout
                                    .as_deref()
                                    .map(|value| parse_duration(Some(value))),
                                strategy: strategy.as_deref(),
                                client_subnet: client_subnet.as_deref(),
                            },
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
pub(super) async fn evaluate_stream_tcp_route<S>(
    stream: &mut S,
    destination: vless::Destination,
    input: RouteInput<'_>,
) -> Result<(RouteEvaluation, Vec<u8>)>
where
    S: AsyncRead + Unpin,
{
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
    let mut initial = Vec::new();
    let mut detected_protocol = None;
    let mut detected_client = None;
    let clash_mode = std::env::var("XHTTP_CLASH_MODE").ok();
    let mut options = router.default_options();
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
                rewrite_ttl,
                client_subnet,
            } => {
                if let (Some(name), Some(resolver)) = (domain.as_deref(), resolver) {
                    destination_ip = select_address(
                        resolve_for_route(
                            resolver,
                            name,
                            crate::dns::LookupOptions {
                                server: server.as_deref(),
                                disable_cache,
                                rewrite_ttl,
                                timeout: timeout
                                    .as_deref()
                                    .map(|value| parse_duration(Some(value))),
                                strategy: strategy.as_deref(),
                                client_subnet: client_subnet.as_deref(),
                            },
                        )
                        .await?,
                        strategy.as_deref(),
                    );
                }
            }
            RuleAction::Sniff { sniffers, timeout } => {
                if initial.is_empty() {
                    let mut buffer = vec![0; 8192];
                    if let Ok(Ok(length)) = tokio::time::timeout(
                        parse_duration(timeout.as_deref()),
                        stream.read(&mut buffer),
                    )
                    .await
                    {
                        buffer.truncate(length);
                        initial = buffer;
                    }
                }
                if let Some(sniffed) = sniff_payload(&initial, false, &sniffers) {
                    detected_protocol = Some(sniffed.protocol);
                    detected_client = sniffed.client;
                    if sniffed.domain.is_some() {
                        domain = sniffed.domain;
                    }
                }
            }
        }
    };
    Ok((
        RouteEvaluation {
            decision,
            destination: override_destination(destination, &options)?,
            options,
        },
        initial,
    ))
}
pub(super) async fn evaluate_udp_route(
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
    let mut options = router.default_options();
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
                rewrite_ttl,
                client_subnet,
            } => {
                if let (Some(name), Some(resolver)) = (domain.as_deref(), resolver) {
                    destination_ip = select_address(
                        resolve_for_route(
                            resolver,
                            name,
                            crate::dns::LookupOptions {
                                server: server.as_deref(),
                                disable_cache,
                                rewrite_ttl,
                                timeout: timeout
                                    .as_deref()
                                    .map(|value| parse_duration(Some(value))),
                                strategy: strategy.as_deref(),
                                client_subnet: client_subnet.as_deref(),
                            },
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
    options: crate::dns::LookupOptions<'_>,
) -> Result<Vec<IpAddr>> {
    tokio::time::timeout(
        options
            .timeout
            .unwrap_or_else(|| std::time::Duration::from_secs(5)),
        resolver.lookup_with_options(name, &options),
    )
    .await
    .context("route DNS resolution timeout")?
}
pub(super) fn override_destination(
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
pub(super) fn tls_server_name(data: &[u8]) -> Option<String> {
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

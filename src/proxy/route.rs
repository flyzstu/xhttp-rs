use crate::{
    dns::DnsResolver,
    linux_route::LinuxRouteMetadata,
    routing::{ActionLookup, RouteContext, RouteDecision, RouteOptions, Router, RuleAction},
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
    /// Addresses resolved during route evaluation, reused by direct dialers
    /// to avoid a second DNS lookup.
    pub(super) resolved_addresses: Vec<IpAddr>,
}
#[derive(Clone, Copy)]
pub(super) struct RouteInput<'a> {
    pub(super) peer: SocketAddr,
    pub(super) inbound: &'a str,
    pub(super) router: &'a Router,
    pub(super) resolver: Option<&'a DnsResolver>,
    pub(super) linux: &'a LinuxRouteMetadata,
    pub(super) auth_user: Option<&'a str>,
    pub(super) clash_mode: Option<&'a str>,
}

/// Mutable state shared by route evaluation loops: the candidate destination
/// addresses and the lazy-resolution bookkeeping.
struct RouteState {
    domain: Option<String>,
    destination_ip: Option<IpAddr>,
    destination_ips: Vec<IpAddr>,
    cursor: usize,
    resolved: bool,
}

impl RouteState {
    fn new(destination: &vless::Destination) -> Self {
        let (domain, destination_ip) = match destination {
            vless::Destination::Domain(value, _) => (Some(value.clone()), None),
            vless::Destination::Ip(value, _) => (None, Some(*value)),
        };
        Self {
            domain,
            destination_ip,
            destination_ips: Vec::new(),
            cursor: 0,
            resolved: false,
        }
    }

    fn context<'a>(&'a self, input: &'a RouteInput<'_>, destination: &'a vless::Destination, network: &'a str, detected_protocol: Option<&'a str>, detected_client: Option<&'a str>) -> RouteContext<'a> {
        RouteContext {
            domain: self.domain.as_deref(),
            destination_ip: self.destination_ip,
            destination_ips: &self.destination_ips,
            destination_port: Some(destination.port()),
            source_ip: Some(input.peer.ip()),
            source_port: Some(input.peer.port()),
            network: Some(network),
            protocol: detected_protocol,
            client: detected_client,
            inbound: Some(input.inbound),
            auth_user: input.auth_user,
            process_name: input.linux.process_name.as_deref(),
            process_path: input.linux.process_path.as_deref(),
            user: input.linux.user.as_deref(),
            user_id: input.linux.user_id,
            clash_mode: input.clash_mode,
            network_type: input.linux.network_type.as_deref(),
            network_is_expensive: input.linux.network_is_expensive,
            network_is_constrained: input.linux.network_is_constrained,
            wifi_ssid: input.linux.wifi_ssid.as_deref(),
            wifi_bssid: input.linux.wifi_bssid.as_deref(),
            interface_addresses: Some(&input.linux.interface_addresses),
            network_interface_addresses: Some(&input.linux.network_interface_addresses),
            source_mac_address: input.linux.source_mac_address.as_deref(),
            source_hostname: input.linux.source_hostname.as_deref(),
            default_interface_addresses: &input.linux.default_interface_addresses,
            ..Default::default()
        }
    }

    /// Apply a `resolve` route action: resolve the domain (via the action's
    /// server or the router's default_domain_resolver) into candidate
    /// addresses.
    async fn resolve_action(
        &mut self,
        router: &Router,
        resolver: Option<&DnsResolver>,
        action: RuleAction,
    ) -> Result<()> {
        let RuleAction::Resolve {
            server,
            timeout,
            strategy,
            disable_cache,
            rewrite_ttl,
            client_subnet,
        } = action
        else {
            return Ok(());
        };
        let (Some(name), Some(resolver)) = (self.domain.as_deref(), resolver) else {
            return Ok(());
        };
        self.destination_ips = resolve_for_route(
            resolver,
            name,
            crate::dns::LookupOptions {
                server: server
                    .as_deref()
                    .or(router.default_domain_resolver().as_deref()),
                disable_cache,
                rewrite_ttl,
                timeout: timeout.as_deref().map(|value| parse_duration(Some(value))),
                strategy: strategy.as_deref(),
                client_subnet: client_subnet.as_deref(),
            },
        )
        .await?;
        self.destination_ip = select_address(self.destination_ips.clone(), strategy.as_deref());
        self.resolved = true;
        Ok(())
    }

    /// Handle a `NeedResolve` result: resolve the domain once through the
    /// router's default_domain_resolver, retrying the rule on success or
    /// skipping it when resolution yields nothing.
    async fn need_resolve(
        &mut self,
        router: &Router,
        resolver: Option<&DnsResolver>,
        index: usize,
    ) {
        let (Some(name), Some(resolver)) = (self.domain.as_deref(), resolver) else {
            self.cursor = index + 1;
            return;
        };
        let server = router.default_domain_resolver();
        self.destination_ips = resolve_for_route(
            resolver,
            name,
            crate::dns::LookupOptions {
                server: server.as_deref(),
                ..Default::default()
            },
        )
        .await
        .unwrap_or_default();
        self.resolved = true;
        if self.destination_ips.is_empty() {
            self.cursor = index + 1;
        } else {
            self.destination_ip = self.destination_ips.first().copied();
            self.cursor = index;
        }
    }

    fn resolved_addresses(&self) -> Vec<IpAddr> {
        if self.resolved {
            self.destination_ips.clone()
        } else {
            Vec::new()
        }
    }
}

pub(super) async fn evaluate_tcp_route(
    local: &TcpStream,
    initial: &[u8],
    destination: vless::Destination,
    input: RouteInput<'_>,
) -> Result<RouteEvaluation> {
    let RouteInput {
        peer: _,
        inbound: _,
        router,
        resolver,
        linux: _,
        auth_user: _,
        clash_mode: _,
    } = input;
    let mut state = RouteState::new(&destination);
    let mut detected_protocol = None;
    let mut detected_client = None;
    let mut options = router.default_options();
    let decision = loop {
        let context = state.context(&input, &destination, "tcp", detected_protocol.as_deref(), detected_client.as_deref());
        match router.next_action_lazy(&context, state.cursor) {
            ActionLookup::Action { index, action } => {
                let action = *action;
                state.cursor = index + 1;
                match action {
                    RuleAction::Route {
                        decision,
                        options: action_options,
                    } => {
                        options.merge(&action_options);
                        break decision;
                    }
                    RuleAction::RouteOptions(action_options) => options.merge(&action_options),
                    RuleAction::Resolve { .. } => {
                        state.resolve_action(router, resolver, action).await?;
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
                                state.domain = sniffed.domain;
                            }
                        }
                    }
                }
            }
            ActionLookup::NeedResolve { index } => {
                state.need_resolve(router, resolver, index).await;
            }
            ActionLookup::None => {
                break RouteDecision::Outbound(router.final_outbound().to_owned());
            }
        }
    };
    Ok(RouteEvaluation {
        decision,
        destination: override_destination(destination, &options)?,
        options,
        resolved_addresses: state.resolved_addresses(),
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
        peer: _,
        inbound: _,
        router,
        resolver,
        linux: _,
        auth_user: _,
        clash_mode: _,
    } = input;
    let mut state = RouteState::new(&destination);
    let mut initial = Vec::new();
    let mut detected_protocol = None;
    let mut detected_client = None;
    let mut options = router.default_options();
    let decision = loop {
        let context = state.context(&input, &destination, "tcp", detected_protocol.as_deref(), detected_client.as_deref());
        match router.next_action_lazy(&context, state.cursor) {
            ActionLookup::Action { index, action } => {
                let action = *action;
                state.cursor = index + 1;
                match action {
                    RuleAction::Route {
                        decision,
                        options: action_options,
                    } => {
                        options.merge(&action_options);
                        break decision;
                    }
                    RuleAction::RouteOptions(action_options) => options.merge(&action_options),
                    RuleAction::Resolve { .. } => {
                        state.resolve_action(router, resolver, action).await?;
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
                                state.domain = sniffed.domain;
                            }
                        }
                    }
                }
            }
            ActionLookup::NeedResolve { index } => {
                state.need_resolve(router, resolver, index).await;
            }
            ActionLookup::None => {
                break RouteDecision::Outbound(router.final_outbound().to_owned());
            }
        }
    };
    Ok((
        RouteEvaluation {
            decision,
            destination: override_destination(destination, &options)?,
            options,
            resolved_addresses: state.resolved_addresses(),
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
        peer: _,
        inbound: _,
        router,
        resolver,
        linux: _,
        auth_user: _,
        clash_mode: _,
    } = input;
    let mut state = RouteState::new(&destination);
    let mut detected_protocol = None;
    let mut detected_client = None;
    let mut options = router.default_options();
    let decision = loop {
        let context = state.context(&input, &destination, "udp", detected_protocol.as_deref(), detected_client.as_deref());
        match router.next_action_lazy(&context, state.cursor) {
            ActionLookup::Action { index, action } => {
                let action = *action;
                state.cursor = index + 1;
                match action {
                    RuleAction::Route {
                        decision,
                        options: action_options,
                    } => {
                        options.merge(&action_options);
                        break decision;
                    }
                    RuleAction::RouteOptions(action_options) => options.merge(&action_options),
                    RuleAction::Resolve { .. } => {
                        state.resolve_action(router, resolver, action).await?;
                    }
                    RuleAction::Sniff {
                        sniffers,
                        timeout: _,
                    } => {
                        if let Some(sniffed) = sniff_payload(payload, true, &sniffers) {
                            detected_protocol = Some(sniffed.protocol);
                            detected_client = sniffed.client;
                            if sniffed.domain.is_some() {
                                state.domain = sniffed.domain;
                            }
                        }
                    }
                }
            }
            ActionLookup::NeedResolve { index } => {
                state.need_resolve(router, resolver, index).await;
            }
            ActionLookup::None => {
                break RouteDecision::Outbound(router.final_outbound().to_owned());
            }
        }
    };
    Ok(RouteEvaluation {
        decision,
        destination: override_destination(destination, &options)?,
        options,
        resolved_addresses: state.resolved_addresses(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routing::RouteOptions;

    #[test]
    fn sniff_detects_tls_with_server_name() {
        let mut hello = vec![
            1, 0, 0, 0, // handshake header
            0x03, 0x03, // version
        ];
        hello.extend([0u8; 32]); // random
        hello.push(0); // session id length
        hello.extend(0x00u16.to_be_bytes()); // cipher suites length
        hello.push(0); // compression methods length
        hello.extend(0x00u16.to_be_bytes()); // extensions length
        let len = hello.len() as u32;
        hello[1..4].copy_from_slice(&len.to_be_bytes()[1..]);
        let mut record = vec![0x16, 0x03, 0x01];
        record.extend((hello.len() as u16).to_be_bytes());
        record.extend_from_slice(&hello);
        let sniffed = sniff_payload(&record, false, &[]).unwrap();
        assert_eq!(sniffed.protocol, "tls");
    }

    #[test]
    fn tls_server_name_extracts_sni_extension() {
        // Minimal TLS ClientHello carrying a server_name (SNI) extension.
        let mut hello = vec![1, 0, 0, 0, 0x03, 0x03];
        hello.extend([0u8; 32]);
        hello.push(0); // session id
        hello.extend([0, 2, 0x13, 0x01]); // cipher suite TLS_AES_128_GCM_SHA256
        hello.push(1); // compression methods length
        hello.push(0);

        // server_name extension: type(2)=0 len(2) payload[list_len(2) name_type(1) name_len(2) name]
        let name = b"example.com";
        let payload = [
            0x00, 0x0d, // server name list length = 13
            0x00, // name type host_name
            0x00, 0x0b, // name length
        ];
        let mut hello_ext = payload.to_vec();
        hello_ext.extend_from_slice(name);
        let mut extensions = Vec::new();
        extensions.extend(0x0000u16.to_be_bytes()); // extension type server_name
        extensions.extend((hello_ext.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&hello_ext);
        hello.extend((extensions.len() as u16).to_be_bytes()); // total extensions length
        hello.extend_from_slice(&extensions);

        let len = hello.len() as u32;
        hello[1..4].copy_from_slice(&len.to_be_bytes()[1..]);
        let mut record = vec![0x16, 0x03, 0x01];
        record.extend((hello.len() as u16).to_be_bytes());
        record.extend_from_slice(&hello);

        assert_eq!(tls_server_name(&record).as_deref(), Some("example.com"));
        assert_eq!(tls_server_name(b"too short"), None);
    }

    #[test]
    fn sniff_detects_http_and_extracts_host_and_client() {
        let data = b"GET /path HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8\r\n\r\n";
        let sniffed = sniff_payload(data, false, &[]).unwrap();
        assert_eq!(sniffed.protocol, "http");
        assert_eq!(sniffed.domain.as_deref(), Some("example.com"));
        assert_eq!(sniffed.client.as_deref(), Some("curl/8"));
    }

    #[test]
    fn sniff_respects_sniffer_filters() {
        let data = b"SSH-2.0-OpenSSH_9";
        let sniffed = sniff_payload(data, false, &["ssh".into()]).unwrap();
        assert_eq!(sniffed.protocol, "ssh");
        assert!(sniff_payload(data, false, &["http".into()]).is_none());
    }

    #[test]
    fn sniff_detects_udp_protocols() {
        let stun = [0u8, 0, 0, 0, 0x21, 0x12, 0xa4, 0x42];
        assert_eq!(sniff_payload(&stun, true, &[]).unwrap().protocol, "stun");
        let quic = [0xc0u8, 0, 0, 0];
        assert_eq!(sniff_payload(&quic, true, &[]).unwrap().protocol, "quic");
        assert!(sniff_payload(&[0u8; 8], true, &[]).is_none());
    }

    #[test]
    fn dns_detection_and_question_name() {
        let mut query = vec![0u8; 12];
        query[2] = 1; // RD flag
        query[4..6].copy_from_slice(&1u16.to_be_bytes()); // one question
        query.extend(b"\x07example\x03com\x00");
        query.extend(1u16.to_be_bytes()); // qtype A
        query.extend(1u16.to_be_bytes()); // qclass IN
        assert!(is_dns_message(&query, false));
        assert_eq!(dns_question_name(&query, false).as_deref(), Some("example.com"));

        let mut tcp = vec![0u8; 0];
        tcp.extend((query.len() as u16).to_be_bytes());
        tcp.extend_from_slice(&query);
        assert!(is_dns_message(&tcp, true));
        assert_eq!(dns_question_name(&tcp, true).as_deref(), Some("example.com"));
        assert!(!is_dns_message(&[0u8; 4], false));
    }

    #[test]
    fn select_address_applies_strategies() {
        let v4: IpAddr = "192.0.2.1".parse().unwrap();
        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(select_address(vec![v4, v6], Some("ipv4_only")), Some(v4));
        assert_eq!(select_address(vec![v4, v6], Some("ipv6_only")), Some(v6));
        assert_eq!(select_address(vec![v4, v6], Some("prefer_ipv6")), Some(v6));
        assert_eq!(select_address(vec![v6, v4], Some("prefer_ipv4")), Some(v4));
        assert_eq!(select_address(vec![v4, v6], None), Some(v4));
        assert_eq!(select_address(Vec::new(), None), None);
    }

    #[test]
    fn override_destination_applies_address_and_port() {
        let original = vless::Destination::Domain("example.com".into(), 80);
        let options = RouteOptions {
            override_address: Some("192.0.2.5".into()),
            override_port: Some(443),
            ..Default::default()
        };
        assert_eq!(
            override_destination(original, &options).unwrap(),
            vless::Destination::Ip("192.0.2.5".parse().unwrap(), 443)
        );
        let domain_override = RouteOptions {
            override_address: Some("other.test".into()),
            ..Default::default()
        };
        assert_eq!(
            override_destination(
                vless::Destination::Ip("192.0.2.1".parse().unwrap(), 53),
                &domain_override,
            )
            .unwrap(),
            vless::Destination::Domain("other.test".into(), 53)
        );
        assert_eq!(
            override_destination(
                vless::Destination::Domain("example.com".into(), 80),
                &RouteOptions::default(),
            )
            .unwrap(),
            vless::Destination::Domain("example.com".into(), 80)
        );
    }
}

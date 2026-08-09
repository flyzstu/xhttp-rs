use crate::{
    dns::DnsResolver,
    linux_route::LinuxRouteMetadata,
    routing::{RouteDecision, RouteOptions, Router},
    vless,
};
use anyhow::{Context, Result, bail};
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    sync::mpsc,
};

use super::{Dialer, parse_duration};
use super::direct::direct_udp_socket;
use super::route::{RouteEvaluation, RouteInput, evaluate_udp_route};

pub(super) struct UdpAssociateRuntime<'a> {
    pub(super) inbound: &'a str,
    pub(super) router: &'a Router,
    pub(super) resolver: Option<&'a DnsResolver>,
    pub(super) dialers: &'a HashMap<String, Dialer>,
    pub(super) linux_metadata: LinuxRouteMetadata,
    pub(super) auth_user: Option<String>,
}
pub(super) async fn udp_associate(
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
pub(super) async fn relay_dns_tcp(stream: &mut TcpStream, resolver: &DnsResolver) -> Result<()> {
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
pub(super) async fn relay_dns_tcp_stream<S>(
    stream: &mut S,
    initial: Vec<u8>,
    resolver: &DnsResolver,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut prefix = initial.as_slice();
    loop {
        let mut length = [0; 2];
        match read_prefixed_exact(stream, &mut prefix, &mut length).await {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(error) => return Err(error.into()),
        }
        let mut request = vec![0; u16::from_be_bytes(length) as usize];
        read_prefixed_exact(stream, &mut prefix, &mut request).await?;
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
async fn read_prefixed_exact<R>(
    reader: &mut R,
    prefix: &mut &[u8],
    output: &mut [u8],
) -> std::io::Result<()>
where
    R: AsyncRead + Unpin + ?Sized,
{
    let copied = prefix.len().min(output.len());
    output[..copied].copy_from_slice(&prefix[..copied]);
    *prefix = &prefix[copied..];
    reader.read_exact(&mut output[copied..]).await.map(|_| ())
}
pub(super) async fn destination_socket_addr(
    destination: &vless::Destination,
    resolver: Option<&DnsResolver>,
) -> Result<SocketAddr> {
    Ok(SocketAddr::new(
        match destination {
            vless::Destination::Ip(ip, _) => *ip,
            vless::Destination::Domain(domain, _) => resolver
                .context("domain UDP response requires a DNS configuration")?
                .lookup(domain)
                .await?
                .into_iter()
                .next()
                .with_context(|| format!("no address for UDP response domain {domain}"))?,
        },
        destination.port(),
    ))
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
                                socket.recv(&mut response).await.map(|length| (length, target))
                            } else {
                                socket.recv_from(&mut response).await
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
                    (None, Some((length, source))) => {
                        let response_source =
                            udp_response_destination(&destination, source, &options);
                        relay
                            .send_to(
                                &encode_socks_udp(&response_source, &response[..length])?,
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
                        let source = source
                            .as_ref()
                            .map(|source| {
                                udp_response_proxy_destination(&destination, source, &options)
                            })
                            .unwrap_or_else(|| destination.clone());
                        relay
                            .send_to(&encode_socks_udp(&source, &payload)?, client)
                            .await?;
                    }
                    (None, None) => return Ok(()),
                    _ => unreachable!(),
                }
            }
        }
        Dialer::AnyTls { client: anytls } => {
            let destination = to_anytls_destination(&destination);
            let initial = anytls::encode_address(&anytls::uot::magic_destination())?;
            let mut stream = anytls.create_stream(&initial).await?;
            anytls::uot::write_request(
                &mut stream,
                &anytls::uot::Request {
                    is_connect: true,
                    destination: destination.clone(),
                },
            )
            .await?;
            let mut response = vec![0; u16::MAX as usize];
            loop {
                let event = tokio::time::timeout(idle_timeout, async {
                    tokio::select! {
                        packet = packets.recv() => Ok::<_, anyhow::Error>((packet, None)),
                        packet = anytls::uot::read_packet(&mut stream, Some(&destination)) => {
                            let (source, payload) = packet?;
                            Ok((None, Some((source, payload))))
                        }
                    }
                })
                .await
                .context("AnyTLS UDP session idle timeout")??;
                match event {
                    (Some(packet), None) => {
                        anytls::uot::write_packet(&mut stream, &destination, &packet, true).await?;
                    }
                    (None, Some((source, payload))) => {
                        let source = from_anytls_destination(&source);
                        let source = udp_response_proxy_destination(
                            &from_anytls_destination(&destination),
                            &source,
                            &options,
                        );
                        response.clear();
                        response.extend_from_slice(&payload);
                        relay
                            .send_to(&encode_socks_udp(&source, &response)?, client)
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
pub(super) fn to_anytls_destination(destination: &vless::Destination) -> anytls::Address {
    match destination {
        vless::Destination::Ip(ip, port) => anytls::Address::Ip(*ip, *port),
        vless::Destination::Domain(domain, port) => anytls::Address::Domain(domain.clone(), *port),
    }
}
pub(super) fn from_anytls_destination(destination: &anytls::Address) -> vless::Destination {
    match destination {
        anytls::Address::Ip(ip, port) => vless::Destination::Ip(*ip, *port),
        anytls::Address::Domain(domain, port) => vless::Destination::Domain(domain.clone(), *port),
    }
}
pub(super) fn udp_response_destination(
    requested: &vless::Destination,
    source: SocketAddr,
    options: &RouteOptions,
) -> vless::Destination {
    udp_response_proxy_destination(
        requested,
        &vless::Destination::Ip(source.ip(), source.port()),
        options,
    )
}
pub(super) fn udp_response_proxy_destination(
    requested: &vless::Destination,
    source: &vless::Destination,
    options: &RouteOptions,
) -> vless::Destination {
    if !options.udp_disable_domain_unmapping
        && matches!(requested, vless::Destination::Domain(_, _))
    {
        requested.clone()
    } else {
        source.clone()
    }
}
pub(super) async fn resolve_udp(
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
pub(super) fn parse_socks_udp(packet: &[u8]) -> Result<(vless::Destination, &[u8])> {
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
pub(super) fn encode_socks_udp(destination: &vless::Destination, payload: &[u8]) -> Result<Vec<u8>> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socks_udp_round_trips_ipv4_and_domain() {
        let v4 = vless::Destination::Ip("192.0.2.7".parse().unwrap(), 53);
        let encoded = encode_socks_udp(&v4, b"query").unwrap();
        assert_eq!(&encoded[..3], &[0, 0, 0]);
        let (decoded, payload) = parse_socks_udp(&encoded).unwrap();
        assert_eq!(decoded, v4);
        assert_eq!(payload, b"query");

        let domain = vless::Destination::Domain("dns.example".into(), 53);
        let encoded = encode_socks_udp(&domain, b"q").unwrap();
        assert_eq!(encoded[3], 3);
        assert_eq!(encoded[4], 11);
        let (decoded, payload) = parse_socks_udp(&encoded).unwrap();
        assert_eq!(decoded, domain);
        assert_eq!(payload, b"q");
    }

    #[test]
    fn socks_udp_round_trips_ipv6() {
        let v6 = vless::Destination::Ip("2001:db8::9".parse().unwrap(), 443);
        let encoded = encode_socks_udp(&v6, b"data").unwrap();
        assert_eq!(encoded[3], 4);
        let (decoded, payload) = parse_socks_udp(&encoded).unwrap();
        assert_eq!(decoded, v6);
        assert_eq!(payload, b"data");
    }

    #[test]
    fn socks_udp_rejects_malformed_packets() {
        assert!(parse_socks_udp(&[0, 0]).is_err()); // too short
        assert!(parse_socks_udp(&[1, 0, 0]).is_err()); // bad reserved field
        assert!(parse_socks_udp(&[0, 0, 1, 0]).is_err()); // fragmented
        assert!(parse_socks_udp(&[0, 0, 0, 9, 1, 2, 3]).is_err()); // truncated address
        assert!(parse_socks_udp(&[0, 0, 0, 9, 3, 20]).is_err()); // bad address type
    }

    #[test]
    fn domain_name_too_long_is_rejected() {
        let domain = "x".repeat(256);
        let destination = vless::Destination::Domain(domain, 1);
        assert!(encode_socks_udp(&destination, b"").is_err());
    }

    #[test]
    fn udp_response_preserves_domain_unless_disabled() {
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
                },
            ),
            source
        );
        let ip_requested = vless::Destination::Ip("192.0.2.9".parse().unwrap(), 53);
        assert_eq!(
            udp_response_proxy_destination(&ip_requested, &source, &RouteOptions::default()),
            source
        );
    }

    #[test]
    fn anytls_destination_conversions_round_trip() {
        let v4 = vless::Destination::Ip("192.0.2.4".parse().unwrap(), 8443);
        assert_eq!(from_anytls_destination(&to_anytls_destination(&v4)), v4);
        let domain = vless::Destination::Domain("svc.example".into(), 443);
        assert_eq!(from_anytls_destination(&to_anytls_destination(&domain)), domain);
    }
}

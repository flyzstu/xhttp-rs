use crate::{
    dns::DnsResolver,
    linux_route::LinuxRouteMetadata,
    routing::{RouteDecision, RouteOptions},
    vless,
};
use anyhow::{Context, Result, bail};
use futures_util::StreamExt;
use std::net::SocketAddr;
use tokio::{
    io::{AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::mpsc,
};

use super::{Dialer, ProxyRuntime, parse_duration};
use super::direct::{connect_direct, direct_udp_socket};
use super::route::{
    RouteEvaluation, RouteInput, evaluate_stream_tcp_route, evaluate_udp_route, override_destination,
    tls_server_name,
};
use super::udp::{
    destination_socket_addr, from_anytls_destination, relay_dns_tcp_stream, resolve_udp,
    to_anytls_destination, udp_response_destination, udp_response_proxy_destination,
};

pub(crate) async fn relay_anytls_tcp(

    mut stream: anytls::AnyTlsStream,
    destination: anytls::Address,
    source: SocketAddr,
    inbound: &str,
    user: Option<&str>,
    runtime: &ProxyRuntime,
) -> Result<()> {
    let destination = from_anytls_destination(&destination);
    let (evaluation, initial) = evaluate_stream_tcp_route(
        &mut stream,
        destination,
        RouteInput {
            peer: source,
            inbound,
            router: &runtime.router,
            resolver: runtime.resolver.as_deref(),
            linux: &LinuxRouteMetadata::default(),
            auth_user: user,
            clash_mode: runtime.clash_mode().as_deref(),
        },
    )
    .await?;
    let RouteEvaluation {
        decision,
        destination,
        options,
        resolved_addresses,
    } = evaluation;
    if decision == RouteDecision::HijackDns {
        let resolver = runtime
            .resolver
            .as_deref()
            .context("DNS hijack requires a DNS configuration")?;
        stream.handshake_success().await?;
        return relay_dns_tcp_stream(&mut stream, initial, resolver).await;
    }
    let tag = match decision {
        RouteDecision::Outbound(tag) => tag,
        RouteDecision::Reject => {
            if options.reject_method.as_deref() != Some("drop") {
                stream
                    .handshake_failure("connection rejected by route")
                    .await?;
            }
            bail!("AnyTLS inbound connection rejected")
        }
        RouteDecision::HijackDns => unreachable!(),
    };
    let dialer = runtime
        .dialer_for(&tag)
        .with_context(|| format!("unknown outbound: {tag}"))?;
    match &dialer {
        Dialer::Direct => {
            let mut target = tokio::time::timeout(
                options
                    .connect_timeout
                    .as_deref()
                    .map(|value| parse_duration(Some(value)))
                    .unwrap_or_else(|| std::time::Duration::from_secs(5)),
                connect_direct(&destination, runtime.resolver.as_deref(), &options, &resolved_addresses),
            )
            .await
            .context("AnyTLS target connect timeout")??;
            crate::anytls::configure_tcp(&target).context("enable TCP_NODELAY on AnyTLS target")?;
            stream.handshake_success().await?;
            if !initial.is_empty() {
                write_first_packet(&mut target, &initial, &options).await?;
            }
            tokio::io::copy_bidirectional(&mut stream, &mut target).await?;
        }
        Dialer::AnyTls { client } => {
            let encoded = anytls::encode_address(&to_anytls_destination(&destination))?;
            let mut target = client.create_stream(&encoded).await?;
            stream.handshake_success().await?;
            if !initial.is_empty() {
                target.write_all(&initial).await?;
            }
            tokio::io::copy_bidirectional(&mut stream, &mut target).await?;
        }
        Dialer::Vless { client, user, .. } => {
            let mut target = client.connect().await?;
            vless::write_request(&mut target, user, &destination).await?;
            stream.handshake_success().await?;
            vless::read_response(&mut target).await?;
            if !initial.is_empty() {
                target.write_all(&initial).await?;
            }
            tokio::io::copy_bidirectional(&mut stream, &mut target).await?;
        }
        Dialer::Block => {
            stream.handshake_failure("connection blocked").await?;
            bail!("AnyTLS inbound connection blocked")
        }
        Dialer::Group(_) => unreachable!("group dialers are resolved before match"),
    }
    Ok(())
}
pub(crate) async fn relay_tun_tcp(
    mut stream: netstack_smoltcp::TcpStream,
    source: SocketAddr,
    destination: SocketAddr,
    inbound: &str,
    runtime: &ProxyRuntime,
) -> Result<()> {
    let destination = vless::Destination::Ip(destination.ip(), destination.port());
    let (evaluation, initial) = evaluate_stream_tcp_route(
        &mut stream,
        destination,
        RouteInput {
            peer: source,
            inbound,
            router: &runtime.router,
            resolver: runtime.resolver.as_deref(),
            linux: &LinuxRouteMetadata::default(),
            auth_user: None,
            clash_mode: runtime.clash_mode().as_deref(),
        },
    )
    .await?;
    let RouteEvaluation {
        decision,
        destination,
        mut options,
        resolved_addresses,
    } = evaluation;
    if let Some(mark) = runtime.tun_output_mark {
        options.routing_mark = Some(mark);
    }
    if decision == RouteDecision::HijackDns {
        return relay_dns_tcp_stream(
            &mut stream,
            initial,
            runtime
                .resolver
                .as_deref()
                .context("DNS hijack requires a DNS configuration")?,
        )
        .await;
    }
    let tag = match decision {
        RouteDecision::Outbound(tag) => tag,
        RouteDecision::Reject => bail!("TUN TCP connection rejected by route"),
        RouteDecision::HijackDns => unreachable!(),
    };
    match &runtime
        .dialer_for(&tag)
        .with_context(|| format!("unknown outbound: {tag}"))?
    {
        Dialer::Direct => {
            let mut target = tokio::time::timeout(
                options
                    .connect_timeout
                    .as_deref()
                    .map(|value| parse_duration(Some(value)))
                    .unwrap_or_else(|| std::time::Duration::from_secs(5)),
                connect_direct(&destination, runtime.resolver.as_deref(), &options, &resolved_addresses),
            )
            .await
            .context("TUN target connect timeout")??;
            if !initial.is_empty() {
                write_first_packet(&mut target, &initial, &options).await?;
            }
            tokio::io::copy_bidirectional(&mut stream, &mut target).await?;
        }
        Dialer::AnyTls { client } => {
            let encoded = anytls::encode_address(&to_anytls_destination(&destination))?;
            let mut target = client.create_stream(&encoded).await?;
            if !initial.is_empty() {
                target.write_all(&initial).await?;
            }
            tokio::io::copy_bidirectional(&mut stream, &mut target).await?;
        }
        Dialer::Vless { client, user, .. } => {
            let mut target = client.connect().await?;
            vless::write_request(&mut target, user, &destination).await?;
            vless::read_response(&mut target).await?;
            if !initial.is_empty() {
                target.write_all(&initial).await?;
            }
            tokio::io::copy_bidirectional(&mut stream, &mut target).await?;
        }
        Dialer::Block => bail!("TUN TCP connection blocked by outbound"),
        Dialer::Group(_) => unreachable!("group dialers are resolved before match"),
    }
    Ok(())
}
pub(crate) async fn relay_anytls_udp(
    mut stream: anytls::AnyTlsStream,
    request: anytls::uot::Request,
    source: SocketAddr,
    inbound: &str,
    user: Option<&str>,
    runtime: &ProxyRuntime,
) -> Result<()> {
    let first = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        anytls::uot::read_packet(
            &mut stream,
            request.is_connect.then_some(&request.destination),
        ),
    )
    .await
    .context("AnyTLS UoT first packet timeout")??;
    let first_destination = from_anytls_destination(&first.0);
    let evaluation = evaluate_udp_route(
        first_destination,
        &first.1,
        RouteInput {
            peer: source,
            inbound,
            router: &runtime.router,
            resolver: runtime.resolver.as_deref(),
            linux: &LinuxRouteMetadata::default(),
            auth_user: user,
            clash_mode: runtime.clash_mode().as_deref(),
        },
    )
    .await?;
    let RouteEvaluation {
        decision,
        destination,
        options,
        resolved_addresses: _,
    } = evaluation;
    let routed_destination = to_anytls_destination(&destination);
    if decision == RouteDecision::HijackDns {
        let resolver = runtime
            .resolver
            .as_deref()
            .context("DNS hijack requires a DNS configuration")?;
        stream.handshake_success().await?;
        return relay_anytls_dns_udp(
            &mut stream,
            &request,
            (routed_destination, first.1),
            resolver,
            &options,
        )
        .await;
    }
    let tag = match decision {
        RouteDecision::Outbound(tag) => tag,
        RouteDecision::Reject => {
            if options.reject_method.as_deref() != Some("drop") {
                stream
                    .handshake_failure("UDP connection rejected by route")
                    .await?;
            }
            bail!("AnyTLS UDP connection rejected")
        }
        RouteDecision::HijackDns => unreachable!(),
    };
    match &runtime
        .dialer_for(&tag)
        .with_context(|| format!("unknown outbound: {tag}"))?
    {
        Dialer::Direct => {
            stream.handshake_success().await?;
            relay_anytls_udp_direct(
                &mut stream,
                &request,
                (routed_destination, first.1),
                runtime.resolver.as_deref(),
                &options,
            )
            .await?;
        }
        Dialer::AnyTls { client } => {
            let encoded = anytls::encode_address(&anytls::uot::magic_destination())?;
            let mut target = client.create_stream(&encoded).await?;
            let target_request = anytls::uot::Request {
                is_connect: request.is_connect,
                destination: routed_destination.clone(),
            };
            anytls::uot::write_request(&mut target, &target_request).await?;
            anytls::uot::write_packet(
                &mut target,
                &routed_destination,
                &first.1,
                request.is_connect,
            )
            .await?;
            stream.handshake_success().await?;
            tokio::io::copy_bidirectional(&mut stream, &mut target).await?;
        }
        Dialer::Vless { client, user, xudp } => {
            if !*xudp && !request.is_connect {
                stream
                    .handshake_failure("unconnected UoT requires VLESS XUDP")
                    .await?;
                bail!("unconnected UoT requires VLESS XUDP")
            }
            let mut target = client.connect().await?;
            let initial_destination = destination;
            vless::write_request_with_command(
                &mut target,
                user,
                if *xudp {
                    vless::Command::Xudp
                } else {
                    vless::Command::Udp
                },
                &initial_destination,
            )
            .await?;
            vless::read_response(&mut target).await?;
            if *xudp {
                vless::write_xudp_packet(&mut target, true, &initial_destination, &first.1).await?;
            } else {
                target
                    .write_u16(first.1.len().try_into().context("UDP packet too large")?)
                    .await?;
                target.write_all(&first.1).await?;
                target.flush().await?;
            }
            stream.handshake_success().await?;
            let (mut inbound_read, mut inbound_write) = tokio::io::split(stream);
            let (mut target_read, mut target_write) = tokio::io::split(target);
            let mut first_xudp_packet = false;
            let mut response = vec![0; u16::MAX as usize];
            loop {
                tokio::select! {
                    packet = anytls::uot::read_packet(
                        &mut inbound_read,
                        request.is_connect.then_some(&request.destination),
                    ) => {
                        let (destination, payload) = packet?;
                        if *xudp {
                            vless::write_xudp_packet(
                                &mut target_write,
                                first_xudp_packet,
                                &from_anytls_destination(&destination),
                                &payload,
                            ).await?;
                            first_xudp_packet = false;
                        } else {
                            target_write
                                .write_u16(payload.len().try_into().context("UDP packet too large")?)
                                .await?;
                            target_write.write_all(&payload).await?;
                            target_write.flush().await?;
                        }
                    }
                    packet = async {
                        if *xudp {
                            let (source, payload) = vless::read_xudp_packet(&mut target_read).await?;
                            Ok::<_, anyhow::Error>((
                                source.unwrap_or_else(|| initial_destination.clone()),
                                payload,
                            ))
                        } else {
                            let length = target_read.read_u16().await? as usize;
                            target_read.read_exact(&mut response[..length]).await?;
                            Ok((initial_destination.clone(), response[..length].to_vec()))
                        }
                    } => {
                        let (source, payload) = packet?;
                        anytls::uot::write_packet(
                            &mut inbound_write,
                            &to_anytls_destination(&source),
                            &payload,
                            request.is_connect,
                        ).await?;
                    }
                }
            }
        }
        Dialer::Block => {
            stream.handshake_failure("UDP connection blocked").await?;
            bail!("AnyTLS UDP connection blocked")
        }
        Dialer::Group(_) => unreachable!("group dialers are resolved before match"),
    }
    Ok(())
}
pub(super) async fn write_first_packet<W>(remote: &mut W, packet: &[u8], options: &RouteOptions) -> Result<()>
where
    W: AsyncWrite + Unpin + ?Sized,
{
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
async fn relay_anytls_dns_udp(
    stream: &mut anytls::AnyTlsStream,
    request: &anytls::uot::Request,
    first: (anytls::Address, Vec<u8>),
    resolver: &DnsResolver,
    options: &RouteOptions,
) -> Result<()> {
    let idle_timeout = options
        .udp_timeout
        .as_deref()
        .map(|value| parse_duration(Some(value)))
        .unwrap_or_else(|| std::time::Duration::from_secs(120));
    let mut packet = Some(first);
    loop {
        let (destination, payload) = match packet.take() {
            Some(packet) => packet,
            None => tokio::time::timeout(
                idle_timeout,
                anytls::uot::read_packet(
                    stream,
                    request.is_connect.then_some(&request.destination),
                ),
            )
            .await
            .context("AnyTLS hijacked DNS UDP idle timeout")??,
        };
        let response = resolver.exchange(&payload).await?;
        anytls::uot::write_packet(stream, &destination, &response, request.is_connect).await?;
    }
}
async fn relay_anytls_udp_direct(
    stream: &mut anytls::AnyTlsStream,
    request: &anytls::uot::Request,
    first: (anytls::Address, Vec<u8>),
    resolver: Option<&DnsResolver>,
    options: &RouteOptions,
) -> Result<()> {
    let first_destination = from_anytls_destination(&first.0);
    let first_target = resolve_udp(&first_destination, resolver).await?;
    let socket = direct_udp_socket(first_target, options)?;
    let connected = request.is_connect || options.udp_connect;
    if connected {
        socket.connect(first_target).await?;
    }
    if connected {
        socket.send(&first.1).await?;
    } else {
        socket.send_to(&first.1, first_target).await?;
    }
    let idle_timeout = options
        .udp_timeout
        .as_deref()
        .map(|value| parse_duration(Some(value)))
        .unwrap_or_else(|| std::time::Duration::from_secs(120));
    let mut response = vec![0; u16::MAX as usize];
    loop {
        let event = tokio::time::timeout(idle_timeout, async {
            tokio::select! {
                packet = anytls::uot::read_packet(
                    stream,
                    request.is_connect.then_some(&request.destination),
                ) => Ok::<_, anyhow::Error>((Some(packet?), None)),
                received = async {
                    if connected {
                        socket.recv(&mut response).await.map(|length| (length, first_target))
                    } else {
                        socket.recv_from(&mut response).await
                    }
                } => Ok((None, Some(received?))),
            }
        })
        .await
        .context("AnyTLS direct UDP idle timeout")??;
        match event {
            (Some((destination, payload)), None) => {
                if connected {
                    socket.send(&payload).await?;
                } else {
                    let destination =
                        override_destination(from_anytls_destination(&destination), options)?;
                    socket
                        .send_to(&payload, resolve_udp(&destination, resolver).await?)
                        .await?;
                }
            }
            (None, Some((length, source))) => {
                let response_source = udp_response_destination(&first_destination, source, options);
                anytls::uot::write_packet(
                    stream,
                    &to_anytls_destination(&response_source),
                    &response[..length],
                    request.is_connect,
                )
                .await?;
            }
            _ => unreachable!(),
        }
    }
}
pub(crate) async fn relay_tun_udp(
    source: SocketAddr,
    inbound: &str,
    runtime: &ProxyRuntime,
    mut packets: mpsc::Receiver<(Vec<u8>, SocketAddr)>,
    responses: mpsc::Sender<(Vec<u8>, SocketAddr, SocketAddr)>,
    default_idle_timeout: std::time::Duration,
    fixed_destination: bool,
) -> Result<()> {
    let Some((first, packet_destination)) = packets.recv().await else {
        return Ok(());
    };
    let original_destination = packet_destination;
    let evaluation = evaluate_udp_route(
        vless::Destination::Ip(original_destination.ip(), original_destination.port()),
        &first,
        RouteInput {
            peer: source,
            inbound,
            router: &runtime.router,
            resolver: runtime.resolver.as_deref(),
            linux: &LinuxRouteMetadata::default(),
            auth_user: None,
            clash_mode: runtime.clash_mode().as_deref(),
        },
    )
    .await?;
    let RouteEvaluation {
        decision,
        destination,
        mut options,
        resolved_addresses: _,
    } = evaluation;
    if let Some(mark) = runtime.tun_output_mark {
        options.routing_mark = Some(mark);
    }
    if decision == RouteDecision::HijackDns {
        let resolver = runtime
            .resolver
            .as_deref()
            .context("DNS hijack requires a DNS configuration")?;
        let mut packet = Some(first);
        loop {
            let request = match packet.take() {
                Some(value) => value,
                None => match packets.recv().await {
                    Some((value, _)) => value,
                    None => return Ok(()),
                },
            };
            let response = resolver.exchange(&request).await?;
            responses
                .send((response, original_destination, source))
                .await
                .context("TUN UDP response channel closed")?;
        }
    }
    let tag = match decision {
        RouteDecision::Outbound(tag) => tag,
        RouteDecision::Reject => return Ok(()),
        RouteDecision::HijackDns => unreachable!(),
    };
    let dialer = runtime
        .dialer_for(&tag)
        .with_context(|| format!("unknown outbound: {tag}"))?;
    if matches!(&dialer, Dialer::Block) {
        return Ok(());
    }
    let idle_timeout = options
        .udp_timeout
        .as_deref()
        .map(|value| parse_duration(Some(value)))
        .unwrap_or(default_idle_timeout);
    let resolver = runtime.resolver.clone();
    let (initial_tx, initial_rx) = mpsc::channel(1);
    initial_tx.send((first, original_destination)).await.ok();
    drop(initial_tx);
    let mut packets = tokio_stream::wrappers::ReceiverStream::new(initial_rx)
        .chain(tokio_stream::wrappers::ReceiverStream::new(packets));

    match &dialer {
        Dialer::Direct => {
            let target = resolve_udp(&destination, resolver.as_deref()).await?;
            let socket = direct_udp_socket(target, &options)?;
            let connected = options.udp_connect && fixed_destination;
            if connected {
                socket.connect(target).await?;
            }
            let mut response = vec![0; u16::MAX as usize];
            loop {
                let event = tokio::time::timeout(idle_timeout, async {
                    tokio::select! {
                        packet = packets.next() => Ok::<_, anyhow::Error>((packet, None)),
                        received = async {
                            if connected {
                                socket.recv(&mut response).await.map(|length| (length, target))
                            } else {
                                socket.recv_from(&mut response).await
                            }
                        } => Ok((None, Some(received?))),
                    }
                })
                .await
                .context("TUN UDP session idle timeout")??;
                match event {
                    (Some((packet, packet_destination)), None) => {
                        if connected {
                            socket.send(&packet).await?;
                        } else {
                            socket.send_to(&packet, packet_destination).await?;
                        }
                    }
                    (None, Some((length, response_source))) => {
                        let response_source =
                            udp_response_destination(&destination, response_source, &options);
                        let response_source =
                            destination_socket_addr(&response_source, resolver.as_deref()).await?;
                        responses
                            .send((response[..length].to_vec(), response_source, source))
                            .await
                            .context("TUN UDP response channel closed")?;
                    }
                    (None, None) => return Ok(()),
                    _ => unreachable!(),
                }
            }
        }
        Dialer::Vless { client, user, xudp } => {
            let mut stream = client.connect().await?;
            vless::write_request_with_command(
                &mut stream,
                user,
                if *xudp {
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
                        packet = packets.next() => Ok::<_, anyhow::Error>((packet, None)),
                        received = async {
                            if !response_read {
                                vless::read_response(&mut read).await?;
                                response_read = true;
                            }
                            if *xudp {
                                let (address, payload) = vless::read_xudp_packet(&mut read).await?;
                                Ok::<_, anyhow::Error>((address, payload))
                            } else {
                                let length = read.read_u16().await? as usize;
                                read.read_exact(&mut response[..length]).await?;
                                Ok((None, response[..length].to_vec()))
                            }
                        } => Ok((None, Some(received?))),
                    }
                })
                .await
                .context("TUN VLESS UDP session idle timeout")??;
                match event {
                    (Some((packet, packet_destination)), None) => {
                        if *xudp {
                            let packet_destination = vless::Destination::Ip(
                                packet_destination.ip(),
                                packet_destination.port(),
                            );
                            vless::write_xudp_packet(
                                &mut write,
                                first_xudp_packet,
                                &packet_destination,
                                &packet,
                            )
                            .await?;
                            first_xudp_packet = false;
                        } else {
                            if packet_destination != original_destination {
                                bail!(
                                    "classic VLESS UDP cannot change destination within one NAT mapping"
                                )
                            }
                            write
                                .write_u16(packet.len().try_into().context("UDP packet too large")?)
                                .await?;
                            write.write_all(&packet).await?;
                            write.flush().await?;
                        }
                    }
                    (None, Some((address, payload))) => {
                        let response_source = address
                            .as_ref()
                            .map(|value| {
                                udp_response_proxy_destination(&destination, value, &options)
                            })
                            .unwrap_or_else(|| destination.clone());
                        let response_source =
                            destination_socket_addr(&response_source, resolver.as_deref()).await?;
                        responses
                            .send((payload, response_source, source))
                            .await
                            .context("TUN UDP response channel closed")?;
                    }
                    (None, None) => return Ok(()),
                    _ => unreachable!(),
                }
            }
        }
        Dialer::AnyTls { client } => {
            let anytls_destination = to_anytls_destination(&destination);
            let connected = fixed_destination;
            let initial = anytls::encode_address(&anytls::uot::magic_destination())?;
            let mut stream = client.create_stream(&initial).await?;
            anytls::uot::write_request(
                &mut stream,
                &anytls::uot::Request {
                    is_connect: connected,
                    destination: anytls_destination.clone(),
                },
            )
            .await?;
            loop {
                let event = tokio::time::timeout(idle_timeout, async {
                    tokio::select! {
                        packet = packets.next() => Ok::<_, anyhow::Error>((packet, None)),
                        packet = anytls::uot::read_packet(
                            &mut stream,
                            connected.then_some(&anytls_destination),
                        ) => {
                            Ok((None, Some(packet?)))
                        }
                    }
                })
                .await
                .context("TUN AnyTLS UDP session idle timeout")??;
                match event {
                    (Some((packet, packet_destination)), None) => {
                        let packet_destination = to_anytls_destination(&vless::Destination::Ip(
                            packet_destination.ip(),
                            packet_destination.port(),
                        ));
                        anytls::uot::write_packet(
                            &mut stream,
                            &packet_destination,
                            &packet,
                            connected,
                        )
                        .await?;
                    }
                    (None, Some((address, payload))) => {
                        let response_source = udp_response_proxy_destination(
                            &destination,
                            &from_anytls_destination(&address),
                            &options,
                        );
                        let response_source =
                            destination_socket_addr(&response_source, resolver.as_deref()).await?;
                        responses
                            .send((payload, response_source, source))
                            .await
                            .context("TUN UDP response channel closed")?;
                    }
                    (None, None) => return Ok(()),
                    _ => unreachable!(),
                }
            }
        }
        Dialer::Block => Ok(()),
        Dialer::Group(_) => unreachable!("group dialers are resolved before match"),
    }
}

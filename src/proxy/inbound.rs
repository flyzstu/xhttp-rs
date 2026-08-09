use crate::{
    dns::DnsResolver,
    routing::{RouteDecision, Router},
    singbox::{DnsConfig, Inbound, Outbound, RouteConfig, User},
    vless,
};
use anyhow::{Context, Result, bail};
use base64::Engine;
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

use super::{BoxIo, Dialer, ProxyRuntime, build_runtime, parse_duration, socket};
use super::direct::connect_direct;
use super::relay::write_first_packet;
use super::route::{RouteEvaluation, RouteInput, evaluate_tcp_route};
use super::udp::{UdpAssociateRuntime, relay_dns_tcp, to_anytls_destination, udp_associate};

pub async fn run_socks(

    inbound: Inbound,
    outbounds: Vec<Outbound>,
    route: Option<RouteConfig>,
    dns: Option<DnsConfig>,
) -> Result<()> {
    if !matches!(inbound.r#type.as_str(), "socks" | "http" | "mixed") {
        bail!("unsupported proxy inbound: {}", inbound.r#type)
    }
    let ProxyRuntime {
        dialers,
        router,
        resolver,
        ..
    } = build_runtime(outbounds, route, dns).await?;
    let listen = socket(
        inbound.listen.as_deref().unwrap_or("127.0.0.1"),
        inbound
            .listen_port
            .context("SOCKS inbound requires listen_port")?,
    );
    let listener = TcpListener::bind(&listen).await?;
    let tag = Arc::new(inbound.tag.unwrap_or_else(|| "socks-in".into()));
    let protocol = Arc::new(inbound.r#type);
    let users = Arc::new(inbound.users);
    loop {
        let (stream, peer) = listener.accept().await?;
        crate::anytls::configure_tcp(&stream).context("enable TCP_NODELAY on proxy inbound")?;
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
    if let Dialer::AnyTls { client } = dialer {
        let anytls_destination = to_anytls_destination(&destination);
        let encoded = anytls::encode_address(&anytls_destination)?;
        let mut remote = client.create_stream(&encoded).await?;
        if !initial.is_empty() {
            remote.write_all(&initial).await?;
        }
        if let Some(reply) = &reply {
            local.write_all(reply).await?;
        }
        tokio::io::copy_bidirectional(&mut local, &mut remote).await?;
    } else if let Dialer::Vless { client, user, .. } = dialer {
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

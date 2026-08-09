use anyhow::{Context, Result, bail};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    str::FromStr,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    sync::mpsc,
};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Destination {
    Ip(IpAddr, u16),
    Domain(String, u16),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Tcp,
    Udp,
    Xudp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub command: Command,
    pub destination: Destination,
}
impl Destination {
    pub fn host(&self) -> String {
        match self {
            Self::Ip(v, _) => v.to_string(),
            Self::Domain(v, _) => v.clone(),
        }
    }
    pub fn port(&self) -> u16 {
        match self {
            Self::Ip(_, p) | Self::Domain(_, p) => *p,
        }
    }
}
pub async fn serve<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    users: &[String],
) -> Result<Request> {
    let version = stream.read_u8().await?;
    if version != 0 {
        bail!("unsupported VLESS version")
    };
    let mut id = [0; 16];
    stream.read_exact(&mut id).await?;
    let id = Uuid::from_bytes(id);
    if !users
        .iter()
        .filter_map(|v| Uuid::parse_str(v).ok())
        .any(|v| v == id)
    {
        bail!("unknown VLESS user")
    };
    let addons = stream.read_u8().await? as usize;
    if addons > 0 {
        let mut skip = vec![0; addons];
        stream.read_exact(&mut skip).await?;
    }
    let command = match stream.read_u8().await? {
        1 => Command::Tcp,
        2 => Command::Udp,
        3 => Command::Xudp,
        value => bail!("unsupported VLESS command {value}"),
    };
    let destination = if command == Command::Xudp {
        Destination::Domain(String::new(), 0)
    } else {
        read_destination(stream).await?
    };
    stream.write_all(&[0, 0]).await?;
    Ok(Request {
        command,
        destination,
    })
}

async fn read_destination<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Destination> {
    let port = stream.read_u16().await?;
    let destination = match stream.read_u8().await? {
        1 => {
            let mut b = [0; 4];
            stream.read_exact(&mut b).await?;
            Destination::Ip(Ipv4Addr::from(b).into(), port)
        }
        2 => {
            let n = stream.read_u8().await? as usize;
            let mut b = vec![0; n];
            stream.read_exact(&mut b).await?;
            Destination::Domain(String::from_utf8(b)?, port)
        }
        3 => {
            let mut b = [0; 16];
            stream.read_exact(&mut b).await?;
            Destination::Ip(Ipv6Addr::from(b).into(), port)
        }
        v => bail!("unknown VLESS address type {v}"),
    };
    Ok(destination)
}
pub async fn connect<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    user: &str,
    destination: &Destination,
) -> Result<()> {
    write_request(stream, user, destination).await?;
    read_response(stream).await
}
pub async fn write_request<S: AsyncWrite + Unpin>(
    stream: &mut S,
    user: &str,
    destination: &Destination,
) -> Result<()> {
    write_request_with_command(stream, user, Command::Tcp, destination).await
}

pub async fn write_request_with_command<S: AsyncWrite + Unpin>(
    stream: &mut S,
    user: &str,
    command: Command,
    destination: &Destination,
) -> Result<()> {
    let id = Uuid::parse_str(user).context("invalid VLESS UUID")?;
    let mut request = vec![0];
    request.extend(id.as_bytes());
    request.extend([
        0,
        match command {
            Command::Tcp => 1,
            Command::Udp => 2,
            Command::Xudp => 3,
        },
    ]);
    if command == Command::Xudp {
        stream.write_all(&request).await?;
        stream.flush().await?;
        return Ok(());
    }
    request.extend(destination.port().to_be_bytes());
    match destination {
        Destination::Ip(IpAddr::V4(ip), _) => {
            request.push(1);
            request.extend(ip.octets())
        }
        Destination::Domain(name, _) => {
            if name.len() > 255 {
                bail!("domain too long")
            };
            request.extend([2, name.len() as u8]);
            request.extend(name.as_bytes())
        }
        Destination::Ip(IpAddr::V6(ip), _) => {
            request.push(3);
            request.extend(ip.octets())
        }
    }
    stream.write_all(&request).await?;
    stream.flush().await?;
    Ok(())
}
pub async fn read_response<S: AsyncRead + Unpin>(stream: &mut S) -> Result<()> {
    let version = stream.read_u8().await?;
    if version != 0 {
        bail!("invalid VLESS response")
    };
    let n = stream.read_u8().await? as usize;
    if n > 0 {
        let mut skip = vec![0; n];
        stream.read_exact(&mut skip).await?;
    }
    Ok(())
}
pub async fn relay<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    request: &Request,
) -> Result<()> {
    match request.command {
        Command::Tcp => {
            let destination = &request.destination;
            let mut target = tokio::time::timeout(
                std::time::Duration::from_secs(10),
                TcpStream::connect((destination.host().as_str(), destination.port())),
            )
            .await
            .context("VLESS target connect timeout")??;
            tokio::io::copy_bidirectional(stream, &mut target).await?;
            Ok(())
        }
        Command::Udp => relay_udp(stream, &request.destination).await,
        Command::Xudp => relay_xudp(stream).await,
    }
}

async fn relay_udp<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    destination: &Destination,
) -> Result<()> {
    let target = tokio::net::lookup_host((destination.host().as_str(), destination.port()))
        .await?
        .next()
        .context("VLESS UDP destination did not resolve")?;
    let socket = UdpSocket::bind(if target.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })
    .await?;
    socket.connect(target).await?;
    let mut stream_buffer = vec![0; u16::MAX as usize];
    let mut udp_buffer = vec![0; u16::MAX as usize];
    loop {
        tokio::select! {
            length = stream.read_u16() => {
                let length = length? as usize;
                stream.read_exact(&mut stream_buffer[..length]).await?;
                socket.send(&stream_buffer[..length]).await?;
            }
            received = socket.recv(&mut udp_buffer) => {
                let length = received?;
                stream.write_u16(length.try_into().context("UDP response is too large")?).await?;
                stream.write_all(&udp_buffer[..length]).await?;
                stream.flush().await?;
            }
        }
    }
}

struct XudpFrame {
    session: u16,
    status: u8,
    destination: Option<Destination>,
    payload: Option<Vec<u8>>,
}

async fn relay_xudp<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) -> Result<()> {
    const MAX_XUDP_SESSIONS: usize = 256;
    const XUDP_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);
    let mut sessions = HashMap::<u16, mpsc::Sender<XudpFrame>>::new();
    let (responses, mut response_receiver) =
        mpsc::channel::<(u16, Destination, Vec<u8>)>(MAX_XUDP_SESSIONS);
    loop {
        tokio::select! {
            frame = read_xudp_frame(stream) => {
                let frame = frame?;
                sessions.retain(|_, sender| !sender.is_closed());
                match frame.status {
                    1 => {
                        if sessions.contains_key(&frame.session) {
                            bail!("duplicate XUDP session {}", frame.session)
                        }
                        if sessions.len() >= MAX_XUDP_SESSIONS {
                            bail!("too many XUDP sessions")
                        }
                        let destination = frame
                            .destination
                            .clone()
                            .context("XUDP new frame has no destination")?;
                        let target = resolve_destination(&destination).await?;
                        let socket = UdpSocket::bind(if target.is_ipv4() {
                            "0.0.0.0:0"
                        } else {
                            "[::]:0"
                        })
                        .await?;
                        let (sender, receiver) = mpsc::channel(32);
                        sessions.insert(frame.session, sender.clone());
                        tokio::spawn(run_xudp_session(
                            frame.session,
                            socket,
                            destination,
                            receiver,
                            responses.clone(),
                            XUDP_IDLE_TIMEOUT,
                        ));
                        sender.send(frame).await.context("start XUDP session")?;
                    }
                    2 | 4 => {
                        let sender = sessions
                            .get(&frame.session)
                            .context("XUDP continuation references unknown session")?
                            .clone();
                        sender.send(frame).await.context("continue XUDP session")?;
                    }
                    3 => {
                        if sessions.remove(&frame.session).is_none() {
                            bail!("XUDP close references unknown session")
                        }
                    }
                    status => bail!("invalid XUDP frame status {status}"),
                }
            }
            response = response_receiver.recv() => {
                let (session, source, payload) =
                    response.context("XUDP response channel closed")?;
                write_xudp_frame(
                    stream,
                    session,
                    2,
                    &source,
                    &payload,
                ).await?;
            }
        }
    }
}

async fn run_xudp_session(
    session: u16,
    socket: UdpSocket,
    mut destination: Destination,
    mut frames: mpsc::Receiver<XudpFrame>,
    responses: mpsc::Sender<(u16, Destination, Vec<u8>)>,
    idle_timeout: std::time::Duration,
) {
    let mut udp_buffer = vec![0; u16::MAX as usize];
    // Resolve lazily and cache the target: the destination usually stays
    // fixed across frames, so avoid a per-frame DNS lookup for domains.
    let mut cached_target: Option<SocketAddr> = None;
    loop {
        let event = tokio::time::timeout(idle_timeout, async {
            tokio::select! {
                frame = frames.recv() => Ok::<_, anyhow::Error>((frame, None)),
                received = socket.recv_from(&mut udp_buffer) => Ok((None, Some(received?))),
            }
        })
        .await;
        let Ok(Ok(event)) = event else {
            return;
        };
        match event {
            (Some(frame), None) => {
                if let Some(value) = frame.destination {
                    destination = value;
                    cached_target = None;
                }
                if let Some(payload) = frame.payload {
                    if cached_target.is_none() {
                        let Ok(target) = resolve_destination(&destination).await else {
                            return;
                        };
                        cached_target = Some(target);
                    }
                    let Some(target) = cached_target else {
                        return;
                    };
                    if socket.send_to(&payload, target).await.is_err() {
                        return;
                    }
                }
            }
            (None, Some((length, source))) => {
                if responses
                    .send((
                        session,
                        Destination::Ip(source.ip(), source.port()),
                        udp_buffer[..length].to_vec(),
                    ))
                    .await
                    .is_err()
                {
                    return;
                }
            }
            (None, None) => return,
            _ => unreachable!(),
        }
    }
}

async fn read_xudp_frame<S: AsyncRead + Unpin>(stream: &mut S) -> Result<XudpFrame> {
    let header_length = stream.read_u16().await? as usize;
    if header_length < 4 {
        bail!("invalid XUDP frame length")
    }
    let session = stream.read_u16().await?;
    let status = stream.read_u8().await?;
    let option = stream.read_u8().await?;
    let destination = if header_length > 4 {
        let mut remaining = vec![0; header_length - 4];
        stream.read_exact(&mut remaining).await?;
        if remaining.first() != Some(&2) {
            bail!("XUDP frame is not UDP")
        }
        Some(parse_destination_bytes(&remaining[1..])?)
    } else {
        None
    };
    let payload = if option & 1 != 0 {
        let length = stream.read_u16().await? as usize;
        let mut payload = vec![0; length];
        stream.read_exact(&mut payload).await?;
        Some(payload)
    } else {
        None
    };
    if option & 2 != 0 {
        bail!("remote XUDP session reported an error")
    }
    Ok(XudpFrame {
        session,
        status,
        destination,
        payload,
    })
}

fn parse_destination_bytes(mut bytes: &[u8]) -> Result<Destination> {
    if bytes.len() < 3 {
        bail!("truncated XUDP destination")
    }
    let port = u16::from_be_bytes([bytes[0], bytes[1]]);
    bytes = &bytes[2..];
    match bytes[0] {
        1 if bytes.len() >= 5 => Ok(Destination::Ip(
            IpAddr::V4(Ipv4Addr::new(bytes[1], bytes[2], bytes[3], bytes[4])),
            port,
        )),
        2 if bytes.len() >= 2 && bytes.len() >= bytes[1] as usize + 2 => {
            let length = bytes[1] as usize;
            Ok(Destination::Domain(
                String::from_utf8(bytes[2..2 + length].to_vec())?,
                port,
            ))
        }
        3 if bytes.len() >= 17 => {
            let mut address = [0; 16];
            address.copy_from_slice(&bytes[1..17]);
            Ok(Destination::Ip(Ipv6Addr::from(address).into(), port))
        }
        _ => bail!("invalid XUDP destination"),
    }
}

async fn write_xudp_frame<S: AsyncWrite + Unpin>(
    stream: &mut S,
    session: u16,
    status: u8,
    destination: &Destination,
    payload: &[u8],
) -> Result<()> {
    let mut address = Vec::new();
    encode_destination_bytes(&mut address, destination)?;
    stream
        .write_u16(
            (5 + address.len())
                .try_into()
                .context("XUDP header too large")?,
        )
        .await?;
    stream.write_u16(session).await?;
    stream.write_all(&[status, 1, 2]).await?;
    stream.write_all(&address).await?;
    stream
        .write_u16(payload.len().try_into().context("XUDP payload too large")?)
        .await?;
    stream.write_all(payload).await?;
    stream.flush().await?;
    Ok(())
}

pub(crate) async fn write_xudp_packet<S: AsyncWrite + Unpin>(
    stream: &mut S,
    new_session: bool,
    destination: &Destination,
    payload: &[u8],
) -> Result<()> {
    write_xudp_frame(
        stream,
        0,
        if new_session { 1 } else { 2 },
        destination,
        payload,
    )
    .await
}

pub(crate) async fn read_xudp_packet<S: AsyncRead + Unpin>(
    stream: &mut S,
) -> Result<(Option<Destination>, Vec<u8>)> {
    loop {
        let frame = read_xudp_frame(stream).await?;
        if frame.status == 3 {
            bail!("XUDP session ended")
        }
        if let Some(payload) = frame.payload {
            return Ok((frame.destination, payload));
        }
    }
}

fn encode_destination_bytes(output: &mut Vec<u8>, destination: &Destination) -> Result<()> {
    output.extend(destination.port().to_be_bytes());
    match destination {
        Destination::Ip(IpAddr::V4(address), _) => {
            output.push(1);
            output.extend(address.octets());
        }
        Destination::Domain(domain, _) => {
            output.extend([2, domain.len().try_into().context("XUDP domain too long")?]);
            output.extend(domain.as_bytes());
        }
        Destination::Ip(IpAddr::V6(address), _) => {
            output.push(3);
            output.extend(address.octets());
        }
    }
    Ok(())
}

async fn resolve_destination(destination: &Destination) -> Result<std::net::SocketAddr> {
    tokio::net::lookup_host((destination.host().as_str(), destination.port()))
        .await?
        .next()
        .context("XUDP destination did not resolve")
}

pub fn parse_destination(host: &str, port: u16) -> Destination {
    IpAddr::from_str(host)
        .map(|v| Destination::Ip(v, port))
        .unwrap_or_else(|_| Destination::Domain(host.into(), port))
}

#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub fn fuzz_destination_bytes(input: &[u8]) {
    let _ = parse_destination_bytes(input);
}

#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub async fn fuzz_xudp_frame(mut input: &[u8]) {
    let _ = read_xudp_frame(&mut input).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn udp_echo() -> std::net::SocketAddr {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buffer = [0; 2048];
            while let Ok((length, peer)) = socket.recv_from(&mut buffer).await {
                if socket.send_to(&buffer[..length], peer).await.is_err() {
                    break;
                }
            }
        });
        address
    }

    #[tokio::test]
    async fn one_xudp_connection_carries_multiple_sessions() {
        let first = udp_echo().await;
        let second = udp_echo().await;
        let (mut client, mut server) = tokio::io::duplex(16 * 1024);
        let relay = tokio::spawn(async move { relay_xudp(&mut server).await });

        write_xudp_frame(
            &mut client,
            10,
            1,
            &Destination::Ip(first.ip(), first.port()),
            b"first",
        )
        .await
        .unwrap();
        write_xudp_frame(
            &mut client,
            20,
            1,
            &Destination::Ip(second.ip(), second.port()),
            b"second",
        )
        .await
        .unwrap();

        let mut responses = HashMap::new();
        for _ in 0..2 {
            let frame = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                read_xudp_frame(&mut client),
            )
            .await
            .unwrap()
            .unwrap();
            responses.insert(frame.session, frame.payload.unwrap());
        }
        assert_eq!(responses.get(&10).unwrap(), b"first");
        assert_eq!(responses.get(&20).unwrap(), b"second");

        write_xudp_frame(
            &mut client,
            10,
            3,
            &Destination::Ip(first.ip(), first.port()),
            &[],
        )
        .await
        .unwrap();
        write_xudp_frame(
            &mut client,
            20,
            3,
            &Destination::Ip(second.ip(), second.port()),
            &[],
        )
        .await
        .unwrap();
        drop(client);
        assert!(relay.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn malformed_xudp_frames_are_rejected() {
        let (mut input, mut parser) = tokio::io::duplex(64);
        input.write_all(&[0, 3, 0, 0, 1]).await.unwrap();
        drop(input);
        assert!(read_xudp_frame(&mut parser).await.is_err());
    }
}

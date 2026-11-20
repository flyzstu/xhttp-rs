use anyhow::{Context, Result, bail};
use rand::Rng;
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU32, Ordering},
    },
    time::Instant,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    sync::{OnceCell, Semaphore, oneshot},
    time::timeout,
};
use tokio_rustls::TlsConnector;

use crate::singbox::DnsServer;

use super::codec::dns_id;
use super::{DNS_TIMEOUT, MAX_DNS_MESSAGE, STREAM_IDLE_TIMEOUT, STREAM_POOL_SIZE};

pub(crate) type DetourUdpFuture<'a> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>>> + Send + 'a>>;
pub(crate) type DetourTcpFuture<'a> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<Box<dyn DnsIo>>> + Send + 'a>>;

/// A UDP datagram channel that can be relayed through a proxy outbound.
pub(crate) trait DnsUdpDetour: Send + Sync {
    /// Send one DNS wire query to `destination` through the outbound `tag`
    /// and return the response wire bytes.
    fn exchange_udp(
        &self,
        tag: &str,
        destination: SocketAddr,
        request: &[u8],
    ) -> DetourUdpFuture<'_>;
    /// Open a TCP stream through the outbound `tag` to `destination`.
    fn connect_tcp(&self, tag: &str, destination: SocketAddr) -> DetourTcpFuture<'_>;
}

/// Shared handle to the detour outbound provider installed by the runtime.
pub(crate) type DnsDetourHandle = std::sync::RwLock<Option<Arc<dyn DnsUdpDetour>>>;

pub(super) struct Upstream {
    pub(super) config: DnsServer,
    endpoint: Option<Arc<Endpoint>>,
    udp: OnceCell<Arc<UdpMultiplexer>>,
    stream: Option<TcpPool>,
    detour: DnsDetourHandle,
    detour_tls: Option<TlsConnector>,
    doh_detour_tls: Option<TlsConnector>,
}
pub(super) struct Endpoint {
    host: String,
    port: u16,
    address: OnceCell<SocketAddr>,
}
type PendingDatagrams =
    Arc<Mutex<HashMap<u16, oneshot::Sender<std::result::Result<Vec<u8>, String>>>>>;
pub(super) struct UdpMultiplexer {
    socket: Arc<UdpSocket>,
    pending: PendingDatagrams,
    next_id: AtomicU32,
}
pub(super) struct TcpPool {
    endpoint: Arc<Endpoint>,
    tls: Option<TlsConnector>,
    idle: Mutex<Vec<IdleConnection>>,
    permits: Arc<Semaphore>,
}
pub(super) struct IdleConnection {
    stream: Box<dyn DnsIo>,
    last_used: Instant,
}
impl Upstream {
    pub(super) fn new(
        config: DnsServer,
        dot_tls: Option<TlsConnector>,
        doh_detour_tls: Option<TlsConnector>,
    ) -> Result<Self> {
        let kind = config.r#type.as_str();
        if !matches!(kind, "" | "udp" | "tcp" | "tls" | "https" | "local") {
            bail!("unsupported DNS server type: {kind}")
        }
        let endpoint = if matches!(kind, "" | "udp" | "tcp" | "tls") {
            let host = config
                .server
                .clone()
                .context("DNS server missing address")?;
            Some(Arc::new(Endpoint {
                host,
                port: config
                    .server_port
                    .unwrap_or(if kind == "tls" { 853 } else { 53 }),
                address: OnceCell::new(),
            }))
        } else {
            None
        };
        let stream = match kind {
            "" | "udp" | "tcp" => Some(TcpPool::new(
                endpoint.clone().expect("stream DNS endpoint"),
                None,
            )),
            "tls" => Some(TcpPool::new(
                endpoint.clone().expect("DoT endpoint"),
                dot_tls.clone(),
            )),
            _ => None,
        };
        Ok(Self {
            config,
            endpoint,
            udp: OnceCell::new(),
            stream,
            detour: DnsDetourHandle::new(None),
            detour_tls: dot_tls,
            doh_detour_tls,
        })
    }

    pub(super) fn set_detour(&self, detour: Arc<dyn DnsUdpDetour>) {
        *self.detour.write().expect("DNS detour lock poisoned") = Some(detour);
    }

    pub(super) async fn query(&self, http: &reqwest::Client, request: &[u8]) -> Result<Vec<u8>> {
        let has_detour = self
            .config
            .detour
            .as_deref()
            .is_some_and(|tag| !tag.is_empty());
        let detour = if has_detour {
            self.detour
                .read()
                .expect("DNS detour lock poisoned")
                .clone()
        } else {
            None
        };
        if let Some(detour) = detour {
            // DoH has no pre-resolved endpoint: the URL itself names the
            // server, and the detour carries the HTTPS connection.
            if self.config.r#type == "https" {
                return query_https_via_detour(
                    &detour,
                    &self.config,
                    request,
                    self.doh_detour_tls.as_ref(),
                )
                .await;
            }
            let endpoint = self
                .endpoint
                .as_ref()
                .context("detour DNS server missing address")?;
            return query_via_detour(
                &detour,
                &self.config,
                endpoint,
                request,
                self.detour_tls.as_ref(),
            )
            .await;
        }
        match self.config.r#type.as_str() {
            "" | "udp" => {
                let endpoint = self.endpoint.as_ref().expect("UDP endpoint");
                let multiplexer = self
                    .udp
                    .get_or_try_init(|| async {
                        UdpMultiplexer::connect(endpoint.resolve().await?).await
                    })
                    .await?;
                let response = multiplexer.query(request).await?;
                if response.get(2).is_some_and(|flags| flags & 2 != 0) {
                    self.stream
                        .as_ref()
                        .expect("UDP TCP fallback pool")
                        .query(request)
                        .await
                } else {
                    Ok(response)
                }
            }
            "tcp" | "tls" => {
                self.stream
                    .as_ref()
                    .expect("stream DNS pool")
                    .query(request)
                    .await
            }
            "https" => query_https(http, &self.config, request).await,
            "local" => bail!("local DNS query requires parsed question"),
            other => bail!("unsupported DNS server type: {other}"),
        }
    }
}
impl Endpoint {
    async fn resolve(&self) -> Result<SocketAddr> {
        self.address
            .get_or_try_init(|| async {
                tokio::net::lookup_host((self.host.as_str(), self.port))
                    .await?
                    .next()
                    .context("DNS server did not resolve")
            })
            .await
            .copied()
    }
}
impl UdpMultiplexer {
    async fn connect(address: SocketAddr) -> Result<Arc<Self>> {
        let socket = Arc::new(
            UdpSocket::bind(if address.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            })
            .await?,
        );
        socket.connect(address).await?;
        let pending: PendingDatagrams = Arc::new(Mutex::new(HashMap::new()));
        let reader_socket = socket.clone();
        let reader_pending = pending.clone();
        tokio::spawn(async move {
            let mut buffer = vec![0; MAX_DNS_MESSAGE];
            loop {
                let length = match reader_socket.recv(&mut buffer).await {
                    Ok(length) => length,
                    Err(error) => {
                        let senders = {
                            let mut pending = reader_pending
                                .lock()
                                .expect("DNS UDP pending lock poisoned");
                            pending
                                .drain()
                                .map(|(_, sender)| sender)
                                .collect::<Vec<_>>()
                        };
                        let message = format!("DNS UDP receive failed: {error}");
                        for sender in senders {
                            let _ = sender.send(Err(message.clone()));
                        }
                        break;
                    }
                };
                let Some(id_bytes) = buffer.get(..2) else {
                    continue;
                };
                let id = u16::from_be_bytes([id_bytes[0], id_bytes[1]]);
                let sender = reader_pending
                    .lock()
                    .expect("DNS UDP pending lock poisoned")
                    .remove(&id);
                if let Some(sender) = sender {
                    let _ = sender.send(Ok(buffer[..length].to_vec()));
                }
            }
        });
        Ok(Arc::new(Self {
            socket,
            pending,
            next_id: AtomicU32::new(rand::rng().random()),
        }))
    }

    async fn query(&self, request: &[u8]) -> Result<Vec<u8>> {
        let original_id = dns_id(request)?;
        let (internal_id, receiver) = {
            let mut pending = self.pending.lock().expect("DNS UDP pending lock poisoned");
            let mut selected = None;
            for _ in 0..=u16::MAX {
                let candidate = self.next_id.fetch_add(1, Ordering::Relaxed) as u16;
                if let std::collections::hash_map::Entry::Vacant(entry) = pending.entry(candidate) {
                    let (sender, receiver) = oneshot::channel();
                    entry.insert(sender);
                    selected = Some((candidate, receiver));
                    break;
                }
            }
            selected.context("DNS UDP transaction ID space exhausted")?
        };
        let mut wire = request.to_vec();
        wire[..2].copy_from_slice(&internal_id.to_be_bytes());
        if let Err(error) = self.socket.send(&wire).await {
            self.pending
                .lock()
                .expect("DNS UDP pending lock poisoned")
                .remove(&internal_id);
            return Err(error.into());
        }
        let received = match timeout(DNS_TIMEOUT, receiver).await {
            Ok(Ok(result)) => result.map_err(anyhow::Error::msg)?,
            Ok(Err(_)) => bail!("DNS UDP response dispatcher stopped"),
            Err(_) => {
                self.pending
                    .lock()
                    .expect("DNS UDP pending lock poisoned")
                    .remove(&internal_id);
                bail!("DNS timeout")
            }
        };
        let mut response = received;
        response
            .get_mut(..2)
            .context("truncated DNS UDP response")?
            .copy_from_slice(&original_id.to_be_bytes());
        Ok(response)
    }
}
impl TcpPool {
    fn new(endpoint: Arc<Endpoint>, tls: Option<TlsConnector>) -> Self {
        Self {
            endpoint,
            tls,
            idle: Mutex::new(Vec::new()),
            permits: Arc::new(Semaphore::new(STREAM_POOL_SIZE)),
        }
    }

    async fn query(&self, request: &[u8]) -> Result<Vec<u8>> {
        let _permit = self
            .permits
            .acquire()
            .await
            .context("DNS stream pool closed")?;
        let mut last_error = None;
        for _ in 0..2 {
            let mut stream = match self.take_idle() {
                Some(stream) => stream,
                None => self.connect().await?,
            };
            match exchange_stream(&mut *stream, request).await {
                Ok(response) => {
                    let mut idle = self.idle.lock().expect("DNS stream pool lock poisoned");
                    if idle.len() < STREAM_POOL_SIZE {
                        idle.push(IdleConnection {
                            stream,
                            last_used: Instant::now(),
                        });
                    }
                    return Ok(response);
                }
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.context("DNS stream query failed")?)
    }

    fn take_idle(&self) -> Option<Box<dyn DnsIo>> {
        let now = Instant::now();
        let mut idle = self.idle.lock().expect("DNS stream pool lock poisoned");
        while let Some(connection) = idle.pop() {
            if now.saturating_duration_since(connection.last_used) < STREAM_IDLE_TIMEOUT {
                return Some(connection.stream);
            }
        }
        None
    }

    async fn connect(&self) -> Result<Box<dyn DnsIo>> {
        let address = self.endpoint.resolve().await?;
        let tcp = timeout(DNS_TIMEOUT, TcpStream::connect(address))
            .await
            .context("DNS connect timeout")??;
        if let Some(connector) = &self.tls {
            let name = rustls::pki_types::ServerName::try_from(self.endpoint.host.clone())
                .context("invalid DoT server name")?;
            Ok(Box::new(connector.connect(name, tcp).await?))
        } else {
            Ok(Box::new(tcp))
        }
    }
}
async fn exchange_stream(stream: &mut dyn DnsIo, q: &[u8]) -> Result<Vec<u8>> {
    stream
        .write_u16(q.len().try_into().context("DNS query too large")?)
        .await?;
    stream.write_all(q).await?;
    stream.flush().await?;
    let n = stream.read_u16().await? as usize;
    let mut response = vec![0; n];
    stream.read_exact(&mut response).await?;
    Ok(response)
}

pub(crate) trait DnsIo: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> DnsIo for T {}

/// Run a DoH query through a detour outbound. Unlike the plain HTTPS path in
/// [`Upstream::query`], the HTTP connection is carried by the detour's TCP
/// stream instead of the global reqwest client, so it inherits the outbound's
/// routing and credentials. The DoH server address is resolved with the local
/// resolver (an IP literal needs no lookup at all) — this is bootstrap only;
/// the actual query travels through the detour.
async fn query_https_via_detour(
    detour: &Arc<dyn DnsUdpDetour>,
    config: &DnsServer,
    request: &[u8],
    tls: Option<&TlsConnector>,
) -> Result<Vec<u8>> {
    let tag = config.detour.as_deref().context("DNS detour tag missing")?;
    let raw = config
        .server
        .as_deref()
        .context("HTTPS DNS server missing address")?;
    let url = if raw.starts_with("http://") || raw.starts_with("https://") {
        url::Url::parse(raw)?
    } else {
        url::Url::parse(&format!("https://{raw}"))?
    };
    let https = url.scheme() == "https";
    let host = url
        .host_str()
        .context("DoH server missing host")?
        .to_string();
    let port = url.port().unwrap_or(if https { 443 } else { 80 });
    let path = if url.path() != "/" && !url.path().is_empty() {
        url.path().to_string()
    } else {
        config.path.clone().unwrap_or_else(|| "/dns-query".into())
    };
    let address = tokio::net::lookup_host((host.as_str(), port))
        .await?
        .next()
        .context("DoH server did not resolve")?;
    let tcp = detour.connect_tcp(tag, address).await?;
    let host_header = if port == if https { 443 } else { 80 } {
        host.clone()
    } else {
        format!("{host}:{port}")
    };
    if https {
        let connector = tls.context("DoH detour TLS configuration unavailable")?;
        let name = rustls::pki_types::ServerName::try_from(host.clone())
            .context("invalid DoH server name")?;
        let mut stream = connector.connect(name, tcp).await?;
        exchange_https(&mut stream, &host_header, &path, request).await
    } else {
        let mut stream = tcp;
        exchange_https(&mut *stream, &host_header, &path, request).await
    }
}

/// Send one DoH POST over an established (possibly TLS) stream and read the
/// single HTTP/1.1 response body.
async fn exchange_https(
    stream: &mut dyn DnsIo,
    host_header: &str,
    path: &str,
    q: &[u8],
) -> Result<Vec<u8>> {
    let head = format!(
        "POST {path} HTTP/1.1\r\nHost: {host_header}\r\nContent-Type: application/dns-message\r\nAccept: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        q.len()
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(q).await?;
    stream.flush().await?;

    let mut reader = tokio::io::BufReader::new(&mut *stream);
    let mut status = false;
    let mut length = None;
    loop {
        let mut line = Vec::new();
        if reader.read_until(b'\n', &mut line).await? == 0 {
            bail!("DoH response ended before headers completed");
        }
        while line
            .last()
            .is_some_and(|byte| *byte == b'\n' || *byte == b'\r')
        {
            line.pop();
        }
        if line.is_empty() {
            break;
        }
        let text = String::from_utf8_lossy(&line);
        if !status && text.starts_with("HTTP/") {
            let code = text
                .split_whitespace()
                .nth(1)
                .and_then(|code| code.parse::<u16>().ok())
                .context("invalid DoH status line")?;
            if !(200..300).contains(&code) {
                bail!("DoH server returned HTTP {code}");
            }
            status = true;
        } else if let Some(value) = text.to_ascii_lowercase().strip_prefix("content-length:") {
            length = Some(
                value
                    .trim()
                    .parse::<usize>()
                    .context("invalid DoH content-length")?,
            );
        }
    }
    if !status {
        bail!("DoH response missing status line");
    }
    let len = length.context("DoH response missing content-length")?;
    if len > MAX_DNS_MESSAGE {
        bail!("DoH response too large: {len}");
    }
    let mut body = vec![0; len];
    reader.read_exact(&mut body).await?;
    Ok(body)
}

/// Run a non-HTTPS DNS query through a detour outbound. UDP servers use the
/// outbound's UDP session (XUDP or AnyTLS UoT); TCP/TLS servers use a TCP
/// stream through the outbound, with TLS applied for `tls` servers. HTTPS
/// servers use [`query_https_via_detour`] instead.
async fn query_via_detour(
    detour: &Arc<dyn DnsUdpDetour>,
    config: &DnsServer,
    endpoint: &Arc<Endpoint>,
    request: &[u8],
    dot_tls: Option<&TlsConnector>,
) -> Result<Vec<u8>> {
    let tag = config.detour.as_deref().context("DNS detour tag missing")?;
    let address = endpoint.resolve().await?;
    match config.r#type.as_str() {
        "" | "udp" => {
            let response = detour.exchange_udp(tag, address, request).await?;
            if response.get(2).is_some_and(|flags| flags & 2 != 0) {
                let mut stream = detour.connect_tcp(tag, address).await?;
                exchange_stream(&mut *stream, request).await
            } else {
                Ok(response)
            }
        }
        "tcp" => {
            let mut stream = detour.connect_tcp(tag, address).await?;
            exchange_stream(&mut *stream, request).await
        }
        "tls" => {
            let tcp = detour.connect_tcp(tag, address).await?;
            let connector = dot_tls.context("DoT detour TLS configuration unavailable")?;
            let server_name = config.server.as_deref().unwrap_or_default().to_owned();
            let name = rustls::pki_types::ServerName::try_from(server_name)
                .context("invalid DoT server name")?;
            let mut stream = connector.connect(name, tcp).await?;
            exchange_stream(&mut stream, request).await
        }
        "https" => bail!("HTTPS DNS over a detour outbound is not supported"),
        "local" => bail!("local DNS server cannot use a detour"),
        other => bail!("unsupported DNS server type for detour: {other}"),
    }
}
async fn query_https(http: &reqwest::Client, s: &DnsServer, q: &[u8]) -> Result<Vec<u8>> {
    let host = s
        .server
        .as_deref()
        .context("HTTPS DNS server missing address")?;
    let path = s.path.as_deref().unwrap_or("/dns-query");
    let url = if host.starts_with("http://") || host.starts_with("https://") {
        format!("{}{}", host.trim_end_matches('/'), path)
    } else {
        format!("https://{host}:{}{path}", s.server_port.unwrap_or(443))
    };
    let r = http
        .post(url)
        .header("content-type", "application/dns-message")
        .header("accept", "application/dns-message")
        .body(q.to_vec())
        .send()
        .await?
        .error_for_status()?;
    Ok(r.bytes().await?.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    struct MockDetour {
        address: SocketAddr,
    }

    impl DnsUdpDetour for MockDetour {
        fn exchange_udp(
            &self,
            _tag: &str,
            _destination: SocketAddr,
            _request: &[u8],
        ) -> DetourUdpFuture<'_> {
            Box::pin(async { bail!("unexpected UDP query in DoH test") })
        }

        fn connect_tcp(&self, tag: &str, _destination: SocketAddr) -> DetourTcpFuture<'_> {
            let address = self.address;
            let tag_ok = tag == "test-detour";
            Box::pin(async move {
                if !tag_ok {
                    bail!("wrong detour tag");
                }
                let stream = TcpStream::connect(address).await?;
                Ok(Box::new(stream) as Box<dyn DnsIo>)
            })
        }
    }

    fn doh_config(address: SocketAddr, path: &str) -> DnsServer {
        DnsServer {
            r#type: "https".into(),
            tag: "dns_doh".into(),
            server: Some(format!("http://{address}{path}")),
            server_port: None,
            path: None,
            detour: Some("test-detour".into()),
        }
    }

    /// Spin up a one-shot DoH server that validates the POST framing and
    /// echoes the request body back as the response body.
    async fn spawn_doh_server(response_body: Vec<u8>, status_line: &'static str) -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 2048];
            let n = stream.read(&mut buf).await.unwrap();
            let request = String::from_utf8_lossy(&buf[..n]);
            assert!(
                request.starts_with("POST /dns-query HTTP/1.1\r\n"),
                "{request}"
            );
            assert!(
                request
                    .to_ascii_lowercase()
                    .contains("content-type: application/dns-message"),
                "{request}"
            );
            let header_end = request.find("\r\n\r\n").expect("request headers");
            assert!(
                request[..header_end]
                    .to_ascii_lowercase()
                    .contains("content-length: 5"),
                "{request}"
            );
            assert_eq!(&buf[header_end + 4..header_end + 9], b"query");
            let response = format!(
                "{status_line}\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                response_body.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
            stream.write_all(&response_body).await.unwrap();
            stream.flush().await.unwrap();
        });
        address
    }

    #[tokio::test]
    async fn doh_over_detour_round_trips_query_and_response() {
        let expected = b"answer".to_vec();
        let address = spawn_doh_server(expected.clone(), "HTTP/1.1 200 OK").await;
        let detour = Arc::new(MockDetour { address }) as Arc<dyn DnsUdpDetour>;
        let response =
            query_https_via_detour(&detour, &doh_config(address, "/dns-query"), b"query", None)
                .await
                .unwrap();
        assert_eq!(response, expected);
    }

    #[tokio::test]
    async fn doh_over_detour_rejects_http_error_status() {
        let address = spawn_doh_server(b"nope".to_vec(), "HTTP/1.1 502 Bad Gateway").await;
        let detour = Arc::new(MockDetour { address }) as Arc<dyn DnsUdpDetour>;
        let error =
            query_https_via_detour(&detour, &doh_config(address, "/dns-query"), b"query", None)
                .await
                .unwrap_err();
        assert!(error.to_string().contains("HTTP 502"), "{error}");
    }
}

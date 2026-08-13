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
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    sync::{OnceCell, Semaphore, oneshot},
    time::timeout,
};
use tokio_rustls::TlsConnector;

use crate::singbox::DnsServer;

use super::message::dns_id;
use super::{MAX_DNS_MESSAGE, STREAM_IDLE_TIMEOUT, STREAM_POOL_SIZE, DNS_TIMEOUT};

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
        })
    }

    pub(super) fn set_detour(&self, detour: Arc<dyn DnsUdpDetour>) {
        *self
            .detour
            .write()
            .expect("DNS detour lock poisoned") = Some(detour);
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
            let endpoint = self.endpoint.as_ref().context("detour DNS server missing address")?;
            return query_via_detour(&detour, &self.config, endpoint, request, self.detour_tls.as_ref()).await;
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

/// Run a DNS query through a detour outbound. UDP servers use the outbound's
/// UDP session (XUDP or AnyTLS UoT); TCP/TLS servers use a TCP stream through
/// the outbound, with TLS applied for `tls` servers. HTTPS DNS over a detour
/// is not supported.
async fn query_via_detour(
    detour: &Arc<dyn DnsUdpDetour>,
    config: &DnsServer,
    endpoint: &Arc<Endpoint>,
    request: &[u8],
    dot_tls: Option<&TlsConnector>,
) -> Result<Vec<u8>> {
    let tag = config
        .detour
        .as_deref()
        .context("DNS detour tag missing")?;
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
            let server_name = config
                .server
                .as_deref()
                .unwrap_or_default()
                .to_owned();
            let name = rustls::pki_types::ServerName::try_from(server_name)
                .context("invalid DoT server name")?;
            let mut stream = connector.connect(name, tcp).await?;
            exchange_stream(&mut stream, request).await
        }
        "https" => bail!("HTTPS DNS over a detour outbound is not supported"),
        "local" => bail!("local DNS server cannot use a detour"),
        other => bail!("unsupported DNS server type for detour: {other}"),
    }
}async fn query_https(http: &reqwest::Client, s: &DnsServer, q: &[u8]) -> Result<Vec<u8>> {
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

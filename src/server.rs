use std::{
    collections::BTreeMap,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

use anyhow::{Context, Result};
use axum::{
    Router,
    body::{Body, Bytes},
    extract::{Request, State},
    http::{Method, StatusCode},
    response::{IntoResponse, Response},
    routing::any,
};
use bytes::Buf;
use dashmap::{DashMap, mapref::entry::Entry};
use futures_util::StreamExt;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{Mutex, mpsc},
};
use tokio_stream::wrappers::ReceiverStream;

use crate::{config::ServerConfig, protocol, vless};

#[derive(Clone)]
pub struct Server {
    state: Arc<ServerState>,
}
struct ServerState {
    config: ServerConfig,
    sessions: DashMap<String, Arc<Session>>,
    active_sessions: AtomicUsize,
}
struct Session {
    sender: mpsc::Sender<Packet>,
    receiver: Mutex<Option<mpsc::Receiver<Packet>>>,
    connected: AtomicBool,
}
struct Packet {
    sequence: u64,
    payload: Bytes,
}

impl Server {
    pub fn new(mut config: ServerConfig) -> Result<Self> {
        config.transport.validate()?;
        if config.target.is_empty() && config.users.is_empty() {
            anyhow::bail!("server requires target or VLESS users")
        }
        for user in &config.users {
            uuid::Uuid::parse_str(user).context("invalid VLESS user UUID")?;
        }
        Ok(Self {
            state: Arc::new(ServerState {
                config,
                sessions: DashMap::new(),
                active_sessions: AtomicUsize::new(0),
            }),
        })
    }
    pub async fn run(self) -> Result<()> {
        crate::install_crypto_provider();
        let addr: SocketAddr = self
            .state
            .config
            .listen
            .parse()
            .context("invalid listen address")?;
        let app = Router::new()
            .route("/{*path}", any(handler))
            .with_state(self.state.clone());
        if let Some(tls) = &self.state.config.tls {
            if tls.http3 {
                return run_h3(addr, self.state.clone(), tls).await;
            }
            let tls = if tls.certificate.contains("BEGIN CERTIFICATE") {
                axum_server::tls_rustls::RustlsConfig::from_pem(
                    tls.certificate.clone().into_bytes(),
                    tls.private_key.clone().into_bytes(),
                )
                .await?
            } else {
                axum_server::tls_rustls::RustlsConfig::from_pem_file(
                    &tls.certificate,
                    &tls.private_key,
                )
                .await?
            };
            axum_server::bind_rustls(addr, tls)
                .serve(app.into_make_service())
                .await?;
        } else {
            let listener = tokio::net::TcpListener::bind(addr).await?;
            axum::serve(listener, app).await?;
        }
        Ok(())
    }
}

async fn run_h3(
    addr: SocketAddr,
    state: Arc<ServerState>,
    tls: &crate::config::ServerTlsConfig,
) -> Result<()> {
    let cert_pem = if tls.certificate.contains("BEGIN CERTIFICATE") {
        tls.certificate.as_bytes().to_vec()
    } else {
        tokio::fs::read(&tls.certificate).await?
    };
    let key_pem = if tls.private_key.contains("BEGIN") {
        tls.private_key.as_bytes().to_vec()
    } else {
        tokio::fs::read(&tls.private_key).await?
    };
    let certs = rustls_pemfile::certs(&mut std::io::Cursor::new(cert_pem))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let key = rustls_pemfile::private_key(&mut std::io::Cursor::new(key_pem))?
        .context("TLS private key is missing")?;
    let mut rustls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    rustls.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(rustls)?;
    let endpoint =
        quinn::Endpoint::server(quinn::ServerConfig::with_crypto(Arc::new(crypto)), addr)?;
    while let Some(incoming) = endpoint.accept().await {
        let state = state.clone();
        tokio::spawn(async move {
            let result: Result<()> = async {
                let connection = incoming.await?;
                let mut h3 = h3::server::builder()
                    .build(h3_quinn::Connection::new(connection))
                    .await?;
                while let Some(resolver) = h3.accept().await? {
                    let state = state.clone();
                    tokio::spawn(async move {
                        let Ok((request, stream)) = resolver.resolve_request().await else {
                            return;
                        };
                        let (mut send, mut recv) = stream.split();
                        let (tx, rx) = mpsc::channel::<Result<Bytes, std::io::Error>>(16);
                        tokio::spawn(async move {
                            loop {
                                match recv.recv_data().await {
                                    Ok(Some(mut data)) => {
                                        let remaining = data.remaining();
                                        if tx.send(Ok(data.copy_to_bytes(remaining))).await.is_err()
                                        {
                                            break;
                                        }
                                    }
                                    Ok(None) => break,
                                    Err(error) => {
                                        let _ = tx
                                            .send(Err(std::io::Error::other(error.to_string())))
                                            .await;
                                        break;
                                    }
                                }
                            }
                        });
                        let request = request.map(|_| Body::from_stream(ReceiverStream::new(rx)));
                        let response = handler(State(state), request).await;
                        let (parts, body) = response.into_parts();
                        if send
                            .send_response(Response::from_parts(parts, ()))
                            .await
                            .is_err()
                        {
                            return;
                        }
                        let mut body = body.into_data_stream();
                        while let Some(Ok(data)) = body.next().await {
                            if send.send_data(data).await.is_err() {
                                return;
                            }
                        }
                        let _ = send.finish().await;
                    });
                }
                Ok(())
            }
            .await;
            if let Err(error) = result {
                tracing::debug!(%error, "HTTP/3 connection closed");
            }
        });
    }
    Ok(())
}

async fn handler(State(state): State<Arc<ServerState>>, request: Request) -> Response {
    let config = state.config.transport.clone();
    if !valid_path(&config.path, request.uri().path())
        || !valid_query(config.query.as_deref(), request.uri().query())
        || config.host.as_ref().is_some_and(|host| {
            request.headers().get("host").and_then(|v| v.to_str().ok()) != Some(host.as_str())
        })
        || !protocol::authorized(&config, request.headers())
        || !protocol::valid_padding(&config, request.uri(), request.headers())
    {
        return StatusCode::NOT_FOUND.into_response();
    }
    if request.method() == Method::OPTIONS {
        return StatusCode::OK.into_response();
    }
    let (session, sequence) = protocol::extract_metadata(&config, request.uri(), request.headers());
    let mut result = match (session, sequence, request.method().clone()) {
        (None, None, Method::POST)
            if matches!(
                config.mode,
                crate::config::Mode::Auto | crate::config::Mode::StreamOne
            ) =>
        {
            stream_one(state, request).await
        }
        (Some(id), None, Method::GET) => download(state, id).await,
        (Some(id), Some(seq), _)
            if matches!(
                config.mode,
                crate::config::Mode::Auto | crate::config::Mode::PacketUp
            ) =>
        {
            packet_upload(state, id, seq, request).await
        }
        (Some(id), None, _)
            if matches!(
                config.mode,
                crate::config::Mode::Auto | crate::config::Mode::StreamUp
            ) =>
        {
            stream_upload(state, id, request).await
        }
        _ => StatusCode::METHOD_NOT_ALLOWED.into_response(),
    };
    protocol::apply_response_padding(&config, result.headers_mut());
    result.headers_mut().insert(
        "access-control-allow-origin",
        axum::http::HeaderValue::from_static("*"),
    );
    if config.no_sse_header {
        result.headers_mut().remove("content-type");
    }
    result
}

async fn stream_one(state: Arc<ServerState>, request: Request) -> Response {
    let stream = backend(&state);
    let (read, mut write) = tokio::io::split(stream);
    let mut input = request.into_body().into_data_stream();
    tokio::spawn(async move {
        while let Some(chunk) = input.next().await {
            match chunk {
                Ok(v) => {
                    if write.write_all(&v).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = write.shutdown().await;
    });
    stream_response(read)
}

async fn download(state: Arc<ServerState>, id: String) -> Response {
    let Some(session) = get_session(&state, &id) else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let mut packets = match session.receiver.lock().await.take() {
        Some(v) => v,
        None => return StatusCode::CONFLICT.into_response(),
    };
    session.connected.store(true, Ordering::Release);
    let stream = backend(&state);
    let (mut read, mut write) = tokio::io::split(stream);
    let (tx, rx) = mpsc::channel::<Result<Bytes, std::io::Error>>(16);
    let state2 = state.clone();
    let id2 = id.clone();
    tokio::spawn(async move {
        let mut pending = BTreeMap::new();
        let mut next = 0;
        while let Some(packet) = packets.recv().await {
            if packet.sequence < next {
                continue;
            }
            if pending.len() >= state2.config.transport.max_buffered_packets
                && !pending.contains_key(&packet.sequence)
            {
                remove_session(&state2, &id2);
                return;
            }
            pending.insert(packet.sequence, packet.payload);
            while let Some(payload) = pending.remove(&next) {
                if write.write_all(&payload).await.is_err() {
                    remove_session(&state2, &id2);
                    return;
                }
                next += 1
            }
        }
        let _ = write.shutdown().await;
    });
    tokio::spawn(async move {
        let mut b = vec![0; 32 * 1024];
        loop {
            match read.read(&mut b).await {
                Ok(0) => break,
                Ok(n) => {
                    if tx.send(Ok(Bytes::copy_from_slice(&b[..n]))).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    let _ = tx.send(Err(e)).await;
                    break;
                }
            }
        }
        remove_session(&state, &id);
    });
    response(Body::from_stream(ReceiverStream::new(rx)))
}

async fn packet_upload(
    state: Arc<ServerState>,
    id: String,
    sequence: u64,
    request: Request,
) -> Response {
    let headers = request.headers().clone();
    let body =
        match axum::body::to_bytes(request.into_body(), state.config.transport.max_packet_size)
            .await
        {
            Ok(v) => v,
            Err(_) => return StatusCode::PAYLOAD_TOO_LARGE.into_response(),
        };
    let payload = match protocol::extract_payload(&state.config.transport, &headers, &body) {
        Ok(v) => Bytes::from(v),
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    if payload.len() > state.config.transport.max_packet_size {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    }
    let Some(session) = get_session(&state, &id) else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    if session
        .sender
        .send(Packet { sequence, payload })
        .await
        .is_err()
    {
        return StatusCode::CONFLICT.into_response();
    }
    StatusCode::OK.into_response()
}

async fn stream_upload(state: Arc<ServerState>, id: String, request: Request) -> Response {
    let Some(session) = get_session(&state, &id) else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let mut input = request.into_body().into_data_stream();
    let (tx, rx) = mpsc::channel::<Result<Bytes, std::io::Error>>(1);
    tokio::spawn(async move {
        let _keep_response_open = tx;
        let mut sequence = 0;
        while let Some(Ok(payload)) = input.next().await {
            if session
                .sender
                .send(Packet { sequence, payload })
                .await
                .is_err()
            {
                break;
            }
            sequence += 1
        }
    });
    response(Body::from_stream(ReceiverStream::new(rx)))
}

fn get_session(state: &Arc<ServerState>, id: &str) -> Option<Arc<Session>> {
    if id.len() > state.config.transport.max_session_id_length {
        return None;
    }
    if let Some(v) = state.sessions.get(id) {
        return Some(v.clone());
    }
    if state
        .active_sessions
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
            (value < state.config.transport.max_sessions).then_some(value + 1)
        })
        .is_err()
    {
        return None;
    }
    let (sender, receiver) = mpsc::channel(state.config.transport.max_buffered_packets);
    let session = Arc::new(Session {
        sender,
        receiver: Mutex::new(Some(receiver)),
        connected: AtomicBool::new(false),
    });
    match state.sessions.entry(id.to_owned()) {
        Entry::Occupied(v) => {
            state.active_sessions.fetch_sub(1, Ordering::AcqRel);
            return Some(v.get().clone());
        }
        Entry::Vacant(v) => {
            v.insert(session.clone());
        }
    }
    let weak = Arc::downgrade(state);
    let id = id.to_owned();
    let timeout = state.config.transport.session_timeout();
    tokio::spawn(async move {
        tokio::time::sleep(timeout).await;
        if let Some(state) = weak.upgrade()
            && state
                .sessions
                .get(&id)
                .is_some_and(|v| !v.connected.load(Ordering::Acquire))
        {
            remove_session(&state, &id);
        }
    });
    Some(session)
}
fn remove_session(state: &ServerState, id: &str) {
    if state.sessions.remove(id).is_some() {
        state.active_sessions.fetch_sub(1, Ordering::AcqRel);
    }
}
fn valid_path(base: &str, path: &str) -> bool {
    path == base || path.strip_prefix(base).is_some_and(|v| v.starts_with('/'))
}
fn valid_query(expected: Option<&str>, actual: Option<&str>) -> bool {
    let Some(expected) = expected else {
        return true;
    };
    let actual: std::collections::HashMap<_, _> = actual
        .map(|query| {
            url::form_urlencoded::parse(query.as_bytes())
                .into_owned()
                .collect()
        })
        .unwrap_or_default();
    url::form_urlencoded::parse(expected.as_bytes()).all(|(key, value)| {
        actual
            .get(key.as_ref())
            .is_some_and(|actual| actual == &value)
    })
}
fn backend(state: &Arc<ServerState>) -> tokio::io::DuplexStream {
    let (front, mut back) =
        tokio::io::duplex(state.config.transport.max_packet_size.max(64 * 1024));
    let users = state.config.users.clone();
    let target = state.config.target.clone();
    tokio::spawn(async move {
        if users.is_empty() {
            match tokio::time::timeout(
                std::time::Duration::from_secs(10),
                tokio::net::TcpStream::connect(&target),
            )
            .await
            {
                Ok(Ok(mut remote)) => {
                    if let Err(error) = tokio::io::copy_bidirectional(&mut back, &mut remote).await
                    {
                        tracing::debug!(%error, %target, "fixed-target relay closed");
                    }
                }
                Ok(Err(error)) => tracing::warn!(%error, %target, "fixed-target connection failed"),
                Err(_) => tracing::warn!(%target, "fixed-target connection timed out"),
            }
        } else {
            match vless::serve(&mut back, &users).await {
                Ok(request) => {
                    if let Err(error) = vless::relay(&mut back, &request).await {
                        tracing::debug!(%error, ?request, "VLESS relay closed");
                    }
                }
                Err(error) => tracing::debug!(%error, "VLESS handshake failed"),
            }
        }
    });
    front
}
fn stream_response<R: tokio::io::AsyncRead + Unpin + Send + 'static>(mut read: R) -> Response {
    let (tx, rx) = mpsc::channel::<Result<Bytes, std::io::Error>>(16);
    tokio::spawn(async move {
        let mut b = vec![0; 32 * 1024];
        loop {
            match read.read(&mut b).await {
                Ok(0) => break,
                Ok(n) => {
                    if tx.send(Ok(Bytes::copy_from_slice(&b[..n]))).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    let _ = tx.send(Err(e)).await;
                    break;
                }
            }
        }
    });
    response(Body::from_stream(ReceiverStream::new(rx)))
}
fn response(body: Body) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header("cache-control", "no-store")
        .header("x-accel-buffering", "no")
        .header("content-type", "text/event-stream")
        .body(body)
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Client,
        config::{ClientConfig, ClientTlsConfig, Mode, TransportConfig},
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn free_addr() -> SocketAddr {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        l.local_addr().unwrap()
    }
    async fn round_trip(mode: Mode) {
        let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = echo.accept().await.unwrap();
            let (mut r, mut w) = s.split();
            let _ = tokio::io::copy(&mut r, &mut w).await;
        });
        let listen = free_addr().await;
        let transport = TransportConfig {
            mode,
            padding_min: 8,
            padding_max: 8,
            packet_interval_ms: 0,
            ..Default::default()
        };
        let server = Server::new(ServerConfig {
            listen: listen.to_string(),
            target: echo_addr.to_string(),
            users: vec![],
            transport: transport.clone(),
            tls: None,
        })
        .unwrap();
        let task = tokio::spawn(server.run());
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let client = Client::new(ClientConfig {
            listen: String::new(),
            server: format!("http://{listen}/xhttp"),
            connect_addr: None,
            transport,
            tls: ClientTlsConfig::default(),
        })
        .unwrap();
        let mut stream = client.connect().await.unwrap();
        stream.write_all(b"mode").await.unwrap();
        let mut result = [0; 4];
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            stream.read_exact(&mut result),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&result, b"mode");
        task.abort();
    }
    #[tokio::test]
    async fn stream_modes_are_full_duplex() {
        round_trip(Mode::StreamOne).await;
        round_trip(Mode::StreamUp).await;
    }

    #[tokio::test]
    async fn ipv6_packet_up_is_full_duplex_when_available() {
        let Ok(echo) = tokio::net::TcpListener::bind("[::1]:0").await else {
            return;
        };
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = echo.accept().await.unwrap();
            let (mut read, mut write) = stream.split();
            let _ = tokio::io::copy(&mut read, &mut write).await;
        });
        let probe = tokio::net::TcpListener::bind("[::1]:0").await.unwrap();
        let listen = probe.local_addr().unwrap();
        drop(probe);
        let transport = TransportConfig {
            mode: Mode::PacketUp,
            padding_min: 8,
            padding_max: 8,
            packet_interval_ms: 0,
            ..Default::default()
        };
        let task = tokio::spawn(
            Server::new(ServerConfig {
                listen: listen.to_string(),
                target: echo_addr.to_string(),
                users: vec![],
                transport: transport.clone(),
                tls: None,
            })
            .unwrap()
            .run(),
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let client = Client::new(ClientConfig {
            listen: String::new(),
            server: format!("http://[::1]:{}/xhttp", listen.port()),
            connect_addr: None,
            transport,
            tls: ClientTlsConfig::default(),
        })
        .unwrap();
        let mut stream = client.connect().await.unwrap();
        stream.write_all(b"ipv6").await.unwrap();
        let mut response = [0; 4];
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            stream.read_exact(&mut response),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&response, b"ipv6");
        task.abort();
    }
    #[tokio::test]
    async fn packet_up_is_full_duplex() {
        let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = echo.accept().await.unwrap();
                tokio::spawn(async move {
                    let (mut r, mut w) = s.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });
        let listen = free_addr().await;
        let transport = TransportConfig {
            mode: Mode::PacketUp,
            padding_min: 8,
            padding_max: 8,
            packet_interval_ms: 0,
            ..Default::default()
        };
        let server = Server::new(ServerConfig {
            listen: listen.to_string(),
            target: echo_addr.to_string(),
            users: vec![],
            transport: transport.clone(),
            tls: None,
        })
        .unwrap();
        let task = tokio::spawn(server.run());
        let client = Client::new(ClientConfig {
            listen: String::new(),
            server: format!("http://{listen}/xhttp"),
            connect_addr: None,
            transport,
            tls: ClientTlsConfig::default(),
        })
        .unwrap();
        let mut stream = loop {
            match client.connect().await {
                Ok(v) => break v,
                Err(_) => tokio::time::sleep(std::time::Duration::from_millis(10)).await,
            }
        };
        stream.write_all(b"hello xhttp").await.unwrap();
        let mut result = [0; 11];
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            stream.read_exact(&mut result),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&result, b"hello xhttp");
        task.abort();
    }

    #[tokio::test]
    async fn packet_reordering_and_session_limit_are_enforced() {
        let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = echo.accept().await.unwrap();
            let (mut read, mut write) = stream.split();
            let _ = tokio::io::copy(&mut read, &mut write).await;
        });
        let server = Server::new(ServerConfig {
            listen: "127.0.0.1:0".into(),
            target: echo_addr.to_string(),
            users: vec![],
            transport: TransportConfig {
                mode: Mode::PacketUp,
                max_sessions: 1,
                ..Default::default()
            },
            tls: None,
        })
        .unwrap();
        let first = get_session(&server.state, "first").unwrap();
        assert!(get_session(&server.state, "second").is_none());
        let response = download(server.state.clone(), "first".into()).await;
        first
            .sender
            .send(Packet {
                sequence: 1,
                payload: Bytes::from_static(b"b"),
            })
            .await
            .unwrap();
        first
            .sender
            .send(Packet {
                sequence: 0,
                payload: Bytes::from_static(b"a"),
            })
            .await
            .unwrap();
        let mut body = response.into_body().into_data_stream();
        let output = tokio::time::timeout(std::time::Duration::from_secs(3), async {
            let mut output = Vec::new();
            while output.len() < 2 {
                output.extend_from_slice(&body.next().await.unwrap().unwrap());
            }
            output
        })
        .await
        .unwrap();
        assert_eq!(output, b"ab");
        remove_session(&server.state, "first");
        assert!(get_session(&server.state, "second").is_some());
    }

    #[tokio::test]
    async fn orphan_sessions_expire_and_release_capacity() {
        let server = Server::new(ServerConfig {
            listen: "127.0.0.1:0".into(),
            target: "127.0.0.1:9".into(),
            users: vec![],
            transport: TransportConfig {
                mode: Mode::PacketUp,
                max_sessions: 1,
                session_timeout_secs: 1,
                ..Default::default()
            },
            tls: None,
        })
        .unwrap();
        assert!(get_session(&server.state, "orphan").is_some());
        assert!(get_session(&server.state, "blocked").is_none());
        tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;
        assert!(get_session(&server.state, "replacement").is_some());
    }

    #[tokio::test]
    async fn malformed_paths_auth_and_oversized_packets_are_rejected() {
        let server = Server::new(ServerConfig {
            listen: "127.0.0.1:0".into(),
            target: "127.0.0.1:9".into(),
            users: vec![],
            transport: TransportConfig {
                mode: Mode::PacketUp,
                token: Some("secret".into()),
                padding_min: 0,
                padding_max: 0,
                max_packet_size: 4,
                ..Default::default()
            },
            tls: None,
        })
        .unwrap();
        let request = Request::builder()
            .uri("/wrong")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            handler(State(server.state.clone()), request).await.status(),
            StatusCode::NOT_FOUND
        );

        let request = Request::builder()
            .method(Method::POST)
            .uri("/xhttp/session/0")
            .header("authorization", "Bearer secret")
            .header("referer", "http://localhost/xhttp?x_padding=")
            .body(Body::from("oversized"))
            .unwrap();
        assert_eq!(
            handler(State(server.state.clone()), request).await.status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
    }

    #[tokio::test]
    async fn concurrent_packet_sessions_do_not_cross_talk() {
        let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = echo.accept().await.unwrap();
                tokio::spawn(async move {
                    let (mut read, mut write) = stream.split();
                    let _ = tokio::io::copy(&mut read, &mut write).await;
                });
            }
        });
        let listen = free_addr().await;
        let transport = TransportConfig {
            mode: Mode::PacketUp,
            padding_min: 8,
            padding_max: 8,
            packet_interval_ms: 0,
            max_sessions: 64,
            ..Default::default()
        };
        let task = tokio::spawn(
            Server::new(ServerConfig {
                listen: listen.to_string(),
                target: echo_addr.to_string(),
                users: vec![],
                transport: transport.clone(),
                tls: None,
            })
            .unwrap()
            .run(),
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let client = Arc::new(
            Client::new(ClientConfig {
                listen: String::new(),
                server: format!("http://{listen}/xhttp"),
                connect_addr: None,
                transport,
                tls: ClientTlsConfig::default(),
            })
            .unwrap(),
        );
        let jobs = (0u32..32).map(|index| {
            let client = client.clone();
            tokio::spawn(async move {
                let payload = format!("session-{index:08}").into_bytes();
                let mut stream = client.connect().await.unwrap();
                stream.write_all(&payload).await.unwrap();
                let mut response = vec![0; payload.len()];
                stream.read_exact(&mut response).await.unwrap();
                assert_eq!(response, payload);
            })
        });
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            futures_util::future::try_join_all(jobs),
        )
        .await
        .unwrap()
        .unwrap();
        task.abort();
    }
    #[tokio::test]
    async fn vless_over_xhttp_reaches_dynamic_target() {
        let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = echo.accept().await.unwrap();
            let (mut r, mut w) = s.split();
            let _ = tokio::io::copy(&mut r, &mut w).await;
        });
        let listen = free_addr().await;
        let user = "e07c0f3b-5ff4-4fd7-833b-df2f4cc90963";
        let transport = TransportConfig {
            mode: Mode::PacketUp,
            padding_min: 8,
            padding_max: 8,
            packet_interval_ms: 0,
            ..Default::default()
        };
        let server = Server::new(ServerConfig {
            listen: listen.to_string(),
            target: String::new(),
            users: vec![user.into()],
            transport: transport.clone(),
            tls: None,
        })
        .unwrap();
        let task = tokio::spawn(server.run());
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let client = Client::new(ClientConfig {
            listen: String::new(),
            server: format!("http://{listen}/xhttp"),
            connect_addr: None,
            transport,
            tls: ClientTlsConfig::default(),
        })
        .unwrap();
        let mut stream = client.connect().await.unwrap();
        vless::connect(
            &mut stream,
            user,
            &vless::parse_destination("127.0.0.1", echo_addr.port()),
        )
        .await
        .unwrap();
        stream.write_all(b"vless").await.unwrap();
        let mut result = [0; 5];
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            stream.read_exact(&mut result),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&result, b"vless");
        task.abort();
    }
    #[tokio::test]
    async fn http3_packet_up_is_full_duplex() {
        let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = echo.accept().await.unwrap();
            let (mut read, mut write) = stream.split();
            let _ = tokio::io::copy(&mut read, &mut write).await;
        });
        let listen = free_addr().await;
        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let transport = TransportConfig {
            mode: Mode::PacketUp,
            padding_min: 8,
            padding_max: 8,
            packet_interval_ms: 0,
            ..Default::default()
        };
        let server = Server::new(ServerConfig {
            listen: listen.to_string(),
            target: echo_addr.to_string(),
            users: vec![],
            transport: transport.clone(),
            tls: Some(crate::config::ServerTlsConfig {
                certificate: cert.pem(),
                private_key: key_pair.serialize_pem(),
                http3: true,
            }),
        })
        .unwrap();
        let task = tokio::spawn(server.run());
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(
            !task.is_finished(),
            "HTTP/3 server exited: {:?}",
            task.await
        );
        let client = Client::new(ClientConfig {
            listen: String::new(),
            server: format!("https://localhost:{}/xhttp", listen.port()),
            connect_addr: Some(listen),
            transport,
            tls: ClientTlsConfig {
                insecure: true,
                http3: true,
                ..Default::default()
            },
        })
        .unwrap();
        let mut stream = client.connect().await.unwrap();
        stream.write_all(b"http3").await.unwrap();
        let mut result = [0; 5];
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            stream.read_exact(&mut result),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&result, b"http3");
        task.abort();
    }
}

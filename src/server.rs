use std::{
    collections::{BTreeMap, VecDeque},
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
    http::{HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::any,
};
use bytes::{Buf, BytesMut};
use dashmap::{DashMap, mapref::entry::Entry};
use futures_util::StreamExt;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{Mutex, Notify, mpsc, oneshot},
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
    downlink: Arc<Mutex<DownlinkState>>,
    connected: AtomicBool,
}

/// Downstream delivery state for one session.
///
/// Every byte the backend produced between `acked` (contiguous position the
/// client confirmed) and `total` (position produced so far) stays buffered in
/// `chunks` until acknowledged. Delivery is by range: a GET attachment or a
/// POST piggyback both snapshot "everything from X" and label the response
/// with `x-dl-from: X`, so the client can deduplicate and reassemble regardless
/// of which path delivered a given byte, and no byte is ever lost unless the
/// client confirmed it first. This is what makes GET reattachment safe.
struct DownlinkState {
    /// `(start_offset, data)` with strictly increasing starts. The head may
    /// start below `acked` (partially acknowledged chunk); consumers trim it.
    chunks: VecDeque<(u64, Bytes)>,
    /// Next offset the backend read loop will produce.
    total: u64,
    /// Contiguous downstream position confirmed received by the client.
    acked: u64,
    max_pending_bytes: usize,
    /// Current GET consumer: `(generation, channel into the response body)`.
    active: Option<(u64, mpsc::Sender<Result<Bytes, std::io::Error>>)>,
    /// Offsets at or above this value are streamed to the live GET directly;
    /// everything below was already included in its attach snapshot.
    deliver_from: u64,
    /// Dropping this sender aborts the previous GET response body.
    kill: Option<oneshot::Sender<()>>,
    /// Set once the backend stream ended; `chunks` may still hold data.
    backend_closed: bool,
    /// Bumped on every GET attachment; the producer snapshots it so it can
    /// detect consumer changes without holding the lock across awaits.
    generation: u64,
    /// Wakes the producer when acknowledgements free buffer space.
    ack_notify: Arc<Notify>,
}

impl DownlinkState {
    fn new(max_pending_bytes: usize) -> Self {
        Self {
            chunks: VecDeque::new(),
            total: 0,
            acked: 0,
            max_pending_bytes,
            active: None,
            deliver_from: 0,
            kill: None,
            backend_closed: false,
            generation: 0,
            ack_notify: Arc::new(Notify::new()),
        }
    }

    /// Record a client acknowledgement. Claims beyond `total` are clamped and
    /// the value never regresses; fully acknowledged chunks are dropped.
    fn acknowledge(&mut self, claim: u64) {
        self.acked = self.acked.max(claim.min(self.total));
        while let Some((offset, chunk)) = self.chunks.front() {
            if *offset + chunk.len() as u64 <= self.acked {
                self.chunks.pop_front();
            } else {
                break;
            }
        }
        self.ack_notify.notify_waiters();
    }

    /// Snapshot the buffered bytes for delivery starting exactly at `from`.
    /// The concatenation of the returned pieces is exactly `[from, ..)`; a
    /// head chunk straddling `from` is trimmed so the first piece starts at
    /// `from` and the client can place the range without re-alignment.
    fn snapshot_from(&self, from: u64) -> Vec<Bytes> {
        let mut pieces = Vec::new();
        for (offset, chunk) in &self.chunks {
            let end = *offset + chunk.len() as u64;
            if end <= from {
                continue;
            }
            if *offset < from {
                let skip = (from - *offset) as usize;
                if skip < chunk.len() {
                    pieces.push(chunk.slice(skip..));
                }
            } else {
                pieces.push(chunk.clone());
            }
        }
        pieces
    }
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
        (Some(id), None, Method::GET) => download(state, id, request.headers().clone()).await,
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
    if config.no_sse_header
        && result
            .headers()
            .get("content-type")
            .is_some_and(|v| v == "text/event-stream")
    {
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

/// End a response body stream as soon as `kill` resolves. Used to terminate
/// a superseded GET consumer without tearing down the session.
fn attach_kill_stream<S>(
    stream: S,
    kill: oneshot::Receiver<()>,
) -> impl futures_util::Stream<Item = S::Item>
where
    S: futures_util::Stream,
{
    #[allow(unused_imports)]
    use tokio_stream::StreamExt as _;
    stream.take_until(kill)
}

async fn download(state: Arc<ServerState>, id: String, headers: HeaderMap) -> Response {
    let Some(session) = get_session(&state, &id) else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    session.connected.store(true, Ordering::Release);

    // Attach to the session's downlink. The pending byte range is snapshotted
    // (never drained through the channel) so attaching cannot deadlock on a
    // full channel no matter how large the backlog is; the snapshot is
    // delivered as the first segment of the response body.
    let ack = headers
        .get("x-dl-ack")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);
    let attach = {
        let mut dl = session.downlink.lock().await;
        dl.acknowledge(ack);
        dl.generation += 1;
        // Abort the previous GET body; if it is still alive this also stops a
        // stale consumer from receiving duplicated data.
        dl.kill = None;
        let closed_empty = dl.backend_closed && dl.snapshot_from(dl.acked).is_empty();
        let mut attached = None;
        if !closed_empty {
            let (tx, rx) = mpsc::channel(64);
            dl.active = Some((dl.generation, tx));
            dl.deliver_from = dl.total;
            let (kill_tx, kill_rx) = oneshot::channel();
            dl.kill = Some(kill_tx);
            attached = Some((rx, kill_rx));
        }
        let preload = dl.snapshot_from(dl.acked);
        (dl.acked, preload, attached)
    };
    let (from, preload, attached) = attach;
    let Some((rx, kill_rx)) = attached else {
        return Response::builder()
            .status(StatusCode::OK)
            .header("x-session-status", "closed")
            .header("x-dl-from", from.to_string())
            .header("cache-control", "no-store")
            .header("x-accel-buffering", "no")
            .header("content-type", "text/event-stream")
            .body(Body::empty())
            .unwrap();
    };
    let body = attach_kill_stream(
        tokio_stream::iter(preload.into_iter().map(Ok::<_, std::io::Error>))
            .chain(ReceiverStream::new(rx)),
        kill_rx,
    );
    Response::builder()
        .status(StatusCode::OK)
        .header("x-dl-from", from.to_string())
        .header("x-session-status", "streaming")
        .header("cache-control", "no-store")
        .header("x-accel-buffering", "no")
        .header("content-type", "text/event-stream")
        .body(Body::from_stream(body))
        .unwrap()
}

async fn packet_upload(
    state: Arc<ServerState>,
    id: String,
    sequence: u64,
    request: Request,
) -> Response {
    let headers = request.headers().clone();
    let client_wants_piggyback =
        headers.get("x-h1-piggyback").and_then(|v| v.to_str().ok()) == Some("1");

    let body =
        match axum::body::to_bytes(request.into_body(), state.config.transport.max_packet_size)
            .await
        {
            Ok(v) => v,
            Err(_) => return StatusCode::PAYLOAD_TOO_LARGE.into_response(),
        };
    let payload = match protocol::extract_payload_bytes(&state.config.transport, &headers, body) {
        Ok(v) => v,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    if payload.len() > state.config.transport.max_packet_size {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    }
    let Some(session) = get_session(&state, &id) else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    session.connected.store(true, Ordering::Release);
    if session
        .sender
        .send(Packet { sequence, payload })
        .await
        .is_err()
    {
        return StatusCode::CONFLICT.into_response();
    }

    if state.config.transport.h1_enable_piggyback && client_wants_piggyback {
        let dl_ack = headers
            .get("x-dl-ack")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0);
        let piggyback = {
            let mut dl = session.downlink.lock().await;
            dl.acknowledge(dl_ack);
            // Skip while a GET consumer is attached: it owns delivery, and
            // skipping avoids double-sending the same bytes. Chunks are NOT
            // removed here; they stay buffered until the client acknowledges
            // them, so a lost piggyback response is recoverable.
            if dl.active.is_none() && !dl.chunks.is_empty() {
                let from = dl.acked;
                let mut combined = BytesMut::new();
                for (offset, chunk) in dl.chunks.iter() {
                    let end = *offset + chunk.len() as u64;
                    if end <= from {
                        continue;
                    }
                    if *offset < from {
                        let skip = (from - *offset) as usize;
                        combined.extend_from_slice(&chunk[skip..]);
                    } else {
                        combined.extend_from_slice(chunk);
                    }
                    if combined.len() >= 32 * 1024 {
                        break;
                    }
                }
                (!combined.is_empty()).then_some((from, combined.freeze()))
            } else {
                None
            }
        };
        if let Some((from, payload)) = piggyback {
            return Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "application/octet-stream")
                .header("x-dl-from", from.to_string())
                .body(Body::from(payload))
                .unwrap();
        }
    }

    Response::builder()
        .status(StatusCode::OK)
        .body(Body::empty())
        .unwrap()
}

async fn stream_upload(state: Arc<ServerState>, id: String, request: Request) -> Response {
    let Some(session) = get_session(&state, &id) else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    session.connected.store(true, Ordering::Release);
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
    let (sender, mut receiver) =
        mpsc::channel::<Packet>(state.config.transport.max_buffered_packets);
    let downlink = Arc::new(Mutex::new(DownlinkState::new(
        state.config.transport.h1_max_pending_bytes,
    )));
    let session = Arc::new(Session {
        sender,
        downlink: downlink.clone(),
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

    let front = backend(state);
    let (mut backend_read, mut backend_write) = tokio::io::split(front);

    let state_upload = Arc::downgrade(state);
    let id_upload = id.to_owned();
    let max_buffered = state.config.transport.max_buffered_packets;

    tokio::spawn(async move {
        let mut pending = BTreeMap::new();
        let mut next = 0;
        while let Some(packet) = receiver.recv().await {
            if packet.sequence < next {
                continue;
            }
            if pending.len() >= max_buffered && !pending.contains_key(&packet.sequence) {
                if let Some(state) = state_upload.upgrade() {
                    remove_session(&state, &id_upload);
                }
                return;
            }
            pending.insert(packet.sequence, packet.payload);
            while let Some(payload) = pending.remove(&next) {
                if backend_write.write_all(&payload).await.is_err() {
                    if let Some(state) = state_upload.upgrade() {
                        remove_session(&state, &id_upload);
                    }
                    return;
                }

                next += 1;
            }
        }
        let _ = backend_write.shutdown().await;
    });

    let downlink_for_read = downlink;
    let state_downlink = Arc::downgrade(state);
    let id_downlink = id.to_owned();
    tokio::spawn(async move {
        let mut buffer = BytesMut::with_capacity(32 * 1024);
        'read: loop {
            // Backpressure: pause reading while the unacknowledged window is
            // full. The lock is never held across the wait.
            while {
                let dl = downlink_for_read.lock().await;
                dl.total - dl.acked > dl.max_pending_bytes as u64
            } {
                let notify = downlink_for_read.lock().await.ack_notify.clone();
                tokio::select! {
                    _ = notify.notified() => {}
                    _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {}
                }
            }
            buffer.clear();
            match backend_read.read_buf(&mut buffer).await {
                Ok(0) => break 'read,
                Ok(_) => {
                    let chunk = buffer.split().freeze();
                    // Append to the range store, then hand the chunk to the
                    // live GET if it falls into that consumer's range. The
                    // send happens OUTSIDE the lock so a stalled consumer
                    // cannot block attaches or piggyback handling; on
                    // consumer death the chunk stays buffered and is
                    // re-delivered by the next attach.
                    let target = {
                        let mut dl = downlink_for_read.lock().await;
                        let offset = dl.total;
                        dl.total += chunk.len() as u64;
                        dl.chunks.push_back((offset, chunk.clone()));
                        dl.active
                            .as_ref()
                            .filter(|_| offset >= dl.deliver_from)
                            .map(|(generation, tx)| (*generation, tx.clone()))
                    };
                    if let Some((generation, tx)) = target {
                        let send_failed = tx.send(Ok(chunk)).await.is_err();
                        if send_failed {
                            let mut dl = downlink_for_read.lock().await;
                            if dl.active.as_ref().is_some_and(|(g, _)| *g == generation) {
                                dl.active = None;
                                dl.kill = None;
                            }
                        }
                    }
                }
                Err(e) => {
                    let target = {
                        let mut dl = downlink_for_read.lock().await;
                        let active = dl.active.take();
                        let kill = dl.kill.take();
                        active.map(|(_, tx)| (tx, kill))
                    };
                    if let Some((tx, _)) = target {
                        let _ = tx.send(Err(e)).await;
                    }
                    break 'read;
                }
            }
        }
        // Backend closed: hand the remaining range to the live consumer, then
        // end its body. Chunks that cannot be delivered stay buffered for a
        // later attachment (within the session lifetime).
        loop {
            let attempt = {
                let mut dl = downlink_for_read.lock().await;
                dl.backend_closed = true;
                match (dl.active.as_ref(), dl.chunks.front()) {
                    (Some((generation, tx)), Some((_, chunk))) => {
                        Some((*generation, tx.clone(), chunk.clone()))
                    }
                    _ => None,
                }
            };
            match attempt {
                Some((generation, tx, chunk)) => {
                    match tokio::time::timeout(
                        std::time::Duration::from_secs(10),
                        tx.send(Ok(chunk.clone())),
                    )
                    .await
                    {
                        Ok(Ok(())) => {
                            let mut dl = downlink_for_read.lock().await;
                            dl.chunks.pop_front();
                        }
                        Ok(Err(_)) | Err(_) => {
                            let mut dl = downlink_for_read.lock().await;
                            if dl.active.as_ref().is_some_and(|(g, _)| *g == generation) {
                                dl.active = None;
                                dl.kill = None;
                            }
                            break;
                        }
                    }
                }
                None => break,
            }
        }
        {
            let mut dl = downlink_for_read.lock().await;
            dl.backend_closed = true;
            dl.active = None;
            dl.kill = None;
        }
        if let Some(state) = state_downlink.upgrade() {
            let timeout = state.config.transport.session_timeout();
            tokio::time::sleep(timeout).await;
            remove_session(&state, &id_downlink);
        }
    });

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

    /// Read exactly `wanted` bytes from a body stream, with a hard timeout per
    /// chunk so a stalled stream fails the test instead of hanging it.
    async fn read_exact_stream(body: &mut axum::body::BodyDataStream, wanted: usize) -> Vec<u8> {
        let mut assembled = Vec::new();
        while assembled.len() < wanted {
            let chunk = tokio::time::timeout(std::time::Duration::from_secs(2), body.next())
                .await
                .expect("stream must deliver buffered data promptly")
                .unwrap()
                .unwrap();
            assembled.extend_from_slice(&chunk);
        }
        assembled
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
        if tokio::net::TcpStream::connect(echo_addr).await.is_err() {
            return;
        }
        let _ = echo.accept().await;
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
        let response = download(server.state.clone(), "first".into(), HeaderMap::new()).await;
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

    #[tokio::test]
    async fn h1_piggyback_delivers_payload_in_post_response() {
        let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = echo.accept().await.unwrap();
            let (mut r, mut w) = s.split();
            let _ = tokio::io::copy(&mut r, &mut w).await;
        });

        let server = Server::new(ServerConfig {
            listen: "127.0.0.1:0".into(),
            target: echo_addr.to_string(),
            users: vec![],
            transport: TransportConfig {
                mode: Mode::PacketUp,
                h1_enable_piggyback: true,
                ..Default::default()
            },
            tls: None,
        })
        .unwrap();

        let session = get_session(&server.state, "piggy-test").unwrap();
        // Insert pending bytes into the downlink store
        {
            let mut dl = session.downlink.lock().await;
            dl.chunks
                .push_back((0, Bytes::from_static(b"piggyback-data")));
            dl.total = 14;
        }

        let request = Request::builder()
            .method(Method::POST)
            .uri("/xhttp/piggy-test/0")
            .header("x-h1-piggyback", "1")
            .header("content-type", "application/octet-stream")
            .body(Body::from(vec![1, 2, 3]))
            .unwrap();

        let response = packet_upload(server.state.clone(), "piggy-test".into(), 0, request).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("content-type").unwrap(),
            "application/octet-stream"
        );
        assert!(response.headers().get("x-ack-seq").is_none());
        assert_eq!(response.headers().get("x-dl-from").unwrap(), "0");
        let body_bytes = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        assert_eq!(body_bytes.as_ref(), b"piggyback-data");

        // Piggyback delivery does not consume the store; the bytes stay
        // buffered until the client acknowledges them.
        {
            let dl = session.downlink.lock().await;
            assert_eq!(dl.chunks.len(), 1);
        }
    }

    #[tokio::test]
    async fn h1_session_resumption_reconnects_download_stream() {
        let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = echo.accept().await.unwrap();
            let (mut r, mut w) = s.split();
            let _ = tokio::io::copy(&mut r, &mut w).await;
        });

        let server = Server::new(ServerConfig {
            listen: "127.0.0.1:0".into(),
            target: echo_addr.to_string(),
            users: vec![],
            transport: TransportConfig {
                mode: Mode::PacketUp,
                h1_enable_session_resumption: true,
                ..Default::default()
            },
            tls: None,
        })
        .unwrap();

        let session = get_session(&server.state, "resume-test").unwrap();
        let res1 = download(server.state.clone(), "resume-test".into(), HeaderMap::new()).await;
        assert_eq!(res1.status(), StatusCode::OK);

        // Upload first packet
        session
            .sender
            .send(Packet {
                sequence: 0,
                payload: Bytes::from_static(b"chunk1"),
            })
            .await
            .unwrap();

        let mut body1 = res1.into_body().into_data_stream();
        let chunk1 = body1.next().await.unwrap().unwrap();
        assert_eq!(chunk1.as_ref(), b"chunk1");

        // Simulate GET disconnect by dropping body1
        drop(body1);

        // Upload second packet while GET is disconnected
        session
            .sender
            .send(Packet {
                sequence: 1,
                payload: Bytes::from_static(b"chunk2"),
            })
            .await
            .unwrap();

        // Give echo server a moment to echo into pending queue
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Reconnect GET stream with the same session id, acknowledging chunk1
        // (the resumed response must start exactly after the acked offset).
        let mut ack_headers = HeaderMap::new();
        ack_headers.insert("x-dl-ack", axum::http::HeaderValue::from_static("6"));
        let res2 = download(server.state.clone(), "resume-test".into(), ack_headers).await;
        assert_eq!(res2.status(), StatusCode::OK);
        assert_eq!(res2.headers().get("x-dl-from").unwrap(), "6");
        let mut body2 = res2.into_body().into_data_stream();
        let chunk2 = body2.next().await.unwrap().unwrap();
        assert_eq!(chunk2.as_ref(), b"chunk2");
    }

    #[tokio::test]
    async fn h1_piggyback_client_server_full_duplex_e2e() {
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
            h1_enable_piggyback: true,
            h1_coalesce_delay_ms: 2,
            h1_enable_session_resumption: true,
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

        stream.write_all(b"e2e-piggyback").await.unwrap();
        let mut result = [0; 13];
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            stream.read_exact(&mut result),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&result, b"e2e-piggyback");
        task.abort();
    }

    #[tokio::test]
    async fn h1_backward_compat_non_piggyback_client() {
        let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = echo.accept().await.unwrap();
            let (mut r, mut w) = s.split();
            let _ = tokio::io::copy(&mut r, &mut w).await;
        });

        // Server has piggyback enabled
        let server = Server::new(ServerConfig {
            listen: "127.0.0.1:0".into(),
            target: echo_addr.to_string(),
            users: vec![],
            transport: TransportConfig {
                mode: Mode::PacketUp,
                h1_enable_piggyback: true,
                ..Default::default()
            },
            tls: None,
        })
        .unwrap();

        let _session = get_session(&server.state, "compat-test").unwrap();
        let get_resp = download(server.state.clone(), "compat-test".into(), HeaderMap::new()).await;
        assert_eq!(get_resp.status(), StatusCode::OK);

        // Upload packet WITHOUT x-h1-piggyback header (like legacy client)
        let request = Request::builder()
            .method(Method::POST)
            .uri("/xhttp/compat-test/0")
            .header("content-type", "application/octet-stream")
            .body(Body::from(b"legacy-client-data".to_vec()))
            .unwrap();

        let post_resp = packet_upload(server.state.clone(), "compat-test".into(), 0, request).await;
        assert_eq!(post_resp.status(), StatusCode::OK);
        // POST response body MUST be empty because client didn't ask for piggybacking!
        let post_body = axum::body::to_bytes(post_resp.into_body(), 1024)
            .await
            .unwrap();
        assert!(
            post_body.is_empty(),
            "legacy client should not receive piggybacked body"
        );

        // GET stream MUST receive all echoed bytes intact
        let mut get_body = get_resp.into_body().into_data_stream();
        let chunk = get_body.next().await.unwrap().unwrap();
        assert_eq!(chunk.as_ref(), b"legacy-client-data");
    }

    #[tokio::test]
    async fn h1_multi_disconnect_session_resumption_stress() {
        let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = echo.accept().await.unwrap();
            let (mut r, mut w) = s.split();
            let _ = tokio::io::copy(&mut r, &mut w).await;
        });

        let server = Server::new(ServerConfig {
            listen: "127.0.0.1:0".into(),
            target: echo_addr.to_string(),
            users: vec![],
            transport: TransportConfig {
                mode: Mode::PacketUp,
                h1_enable_session_resumption: true,
                ..Default::default()
            },
            tls: None,
        })
        .unwrap();

        let session = get_session(&server.state, "multi-resume-test").unwrap();

        // Round 1: Connect GET #1, send seq 0, read chunk, drop GET #1
        let get1 = download(
            server.state.clone(),
            "multi-resume-test".into(),
            HeaderMap::new(),
        )
        .await;
        session
            .sender
            .send(Packet {
                sequence: 0,
                payload: Bytes::from_static(b"packet-zero"),
            })
            .await
            .unwrap();
        let mut body1 = get1.into_body().into_data_stream();
        assert_eq!(
            read_exact_stream(&mut body1, 11).await.as_slice(),
            b"packet-zero"
        );
        drop(body1); // Disconnect #1

        // Round 2: Send seq 1 while disconnected, wait for echo, connect GET #2
        // (acknowledging the 11 delivered bytes), read chunk, drop GET #2
        session
            .sender
            .send(Packet {
                sequence: 1,
                payload: Bytes::from_static(b"packet-one"),
            })
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let mut ack11 = HeaderMap::new();
        ack11.insert("x-dl-ack", axum::http::HeaderValue::from_static("11"));
        let get2 = download(server.state.clone(), "multi-resume-test".into(), ack11).await;
        assert_eq!(get2.headers().get("x-dl-from").unwrap(), "11");
        let mut body2 = get2.into_body().into_data_stream();
        assert_eq!(
            read_exact_stream(&mut body2, 10).await.as_slice(),
            b"packet-one"
        );
        drop(body2); // Disconnect #2

        // Round 3: Send seq 2 while disconnected, connect GET #3 (acked through
        // offset 22), read chunk
        session
            .sender
            .send(Packet {
                sequence: 2,
                payload: Bytes::from_static(b"packet-two"),
            })
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let mut ack21 = HeaderMap::new();
        ack21.insert("x-dl-ack", axum::http::HeaderValue::from_static("21"));
        let get3 = download(server.state.clone(), "multi-resume-test".into(), ack21).await;
        assert_eq!(get3.headers().get("x-dl-from").unwrap(), "21");
        let mut body3 = get3.into_body().into_data_stream();
        assert_eq!(
            read_exact_stream(&mut body3, 10).await.as_slice(),
            b"packet-two"
        );
    }

    #[tokio::test]
    async fn h1_large_payload_bidirectional_stress() {
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
            h1_enable_piggyback: true,
            h1_coalesce_delay_ms: 2,
            h1_enable_session_resumption: true,
            padding_min: 8,
            padding_max: 8,
            packet_interval_ms: 0,
            max_packet_size: 16 * 1024,
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

        let stream = loop {
            match client.connect().await {
                Ok(v) => break v,
                Err(_) => tokio::time::sleep(std::time::Duration::from_millis(10)).await,
            }
        };

        // Send 64KB in chunks
        let total_size = 64 * 1024;
        let payload: Vec<u8> = (0..total_size).map(|i| (i % 251) as u8).collect();
        let payload_clone = payload.clone();

        let (mut client_read, mut client_write) = tokio::io::split(stream);
        let write_task = tokio::spawn(async move {
            for chunk in payload_clone.chunks(4096) {
                client_write.write_all(chunk).await.unwrap();
                tokio::task::yield_now().await;
            }
            client_write.shutdown().await.unwrap();
        });

        let mut received = vec![0u8; total_size];
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            client_read.read_exact(&mut received),
        )
        .await
        .unwrap()
        .unwrap();

        write_task.await.unwrap();
        assert_eq!(received, payload);
        task.abort();
    }

    #[tokio::test]
    async fn vless_over_h1_piggyback_and_resumption() {
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
            h1_enable_piggyback: true,
            h1_coalesce_delay_ms: 2,
            h1_enable_session_resumption: true,
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

        let mut stream = loop {
            match client.connect().await {
                Ok(v) => break v,
                Err(_) => tokio::time::sleep(std::time::Duration::from_millis(10)).await,
            }
        };

        vless::connect(
            &mut stream,
            user,
            &vless::parse_destination("127.0.0.1", echo_addr.port()),
        )
        .await
        .unwrap();

        stream.write_all(b"vless-h1-enhanced").await.unwrap();
        let mut result = [0; 17];
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            stream.read_exact(&mut result),
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(&result, b"vless-h1-enhanced");
        task.abort();
    }

    #[tokio::test]
    async fn h1_client_disabled_piggyback_uses_pure_get() {
        let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = echo.accept().await.unwrap();
            let (mut r, mut w) = s.split();
            let _ = tokio::io::copy(&mut r, &mut w).await;
        });

        let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen = probe.local_addr().unwrap();
        drop(probe);

        let server_transport = TransportConfig {
            mode: Mode::PacketUp,
            h1_enable_piggyback: true,
            h1_enable_session_resumption: true,
            ..Default::default()
        };

        let server = Server::new(ServerConfig {
            listen: listen.to_string(),
            target: echo_addr.to_string(),
            users: vec![],
            transport: server_transport,
            tls: None,
        })
        .unwrap();

        let task = tokio::spawn(server.run());

        let client_transport = TransportConfig {
            mode: Mode::PacketUp,
            h1_enable_piggyback: false,
            h1_enable_session_resumption: true,
            ..Default::default()
        };

        let client = Client::new(ClientConfig {
            listen: String::new(),
            server: format!("http://{listen}/xhttp"),
            connect_addr: None,
            transport: client_transport,
            tls: ClientTlsConfig::default(),
        })
        .unwrap();

        let mut stream = loop {
            match client.connect().await {
                Ok(v) => break v,
                Err(_) => tokio::time::sleep(std::time::Duration::from_millis(10)).await,
            }
        };

        stream.write_all(b"pure-get-stream-payload").await.unwrap();
        let mut buf = [0u8; 23];
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            stream.read_exact(&mut buf),
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(&buf, b"pure-get-stream-payload");
        task.abort();
    }

    #[tokio::test]
    async fn h1_adaptive_coalescing_merges_small_writes() {
        let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = echo.accept().await.unwrap();
            let (mut r, mut w) = s.split();
            let _ = tokio::io::copy(&mut r, &mut w).await;
        });

        let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen = probe.local_addr().unwrap();
        drop(probe);

        let transport = TransportConfig {
            mode: Mode::PacketUp,
            h1_enable_piggyback: true,
            h1_coalesce_delay_ms: 25,
            h1_enable_session_resumption: true,
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

        for i in 1..=5 {
            stream
                .write_all(format!("chunk{i}").as_bytes())
                .await
                .unwrap();
        }

        let mut received = vec![0u8; 30];
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            stream.read_exact(&mut received),
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(&received, b"chunk1chunk2chunk3chunk4chunk5");
        task.abort();
    }

    #[tokio::test]
    async fn h1_concurrent_sessions_piggyback_isolation() {
        let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = echo.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let (mut r, mut w) = s.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });

        let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen = probe.local_addr().unwrap();
        drop(probe);

        let transport = TransportConfig {
            mode: Mode::PacketUp,
            h1_enable_piggyback: true,
            h1_enable_session_resumption: true,
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

        let mut handles = Vec::new();
        for client_id in 0..4 {
            let listen_str = listen.to_string();
            let transport_cfg = transport.clone();
            handles.push(tokio::spawn(async move {
                let client = Client::new(ClientConfig {
                    listen: String::new(),
                    server: format!("http://{listen_str}/xhttp"),
                    connect_addr: None,
                    transport: transport_cfg,
                    tls: ClientTlsConfig::default(),
                })
                .unwrap();

                let mut stream = loop {
                    match client.connect().await {
                        Ok(v) => break v,
                        Err(_) => tokio::time::sleep(std::time::Duration::from_millis(10)).await,
                    }
                };

                let msg = format!("concurrent-client-{client_id}-test-payload");
                stream.write_all(msg.as_bytes()).await.unwrap();

                let mut buf = vec![0u8; msg.len()];
                tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    stream.read_exact(&mut buf),
                )
                .await
                .unwrap()
                .unwrap();

                assert_eq!(buf, msg.as_bytes());
            }));
        }

        for handle in handles {
            handle.await.unwrap();
        }

        task.abort();
    }

    #[tokio::test]
    async fn h1_server_downlink_pending_queue_bounded_capacity() {
        let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();

        let server = Server::new(ServerConfig {
            listen: "127.0.0.1:0".into(),
            target: echo_addr.to_string(),
            users: vec![],
            transport: TransportConfig {
                mode: Mode::PacketUp,
                h1_enable_piggyback: true,
                h1_enable_session_resumption: true,
                ..Default::default()
            },
            tls: None,
        })
        .unwrap();

        let session = get_session(&server.state, "bounded-queue-test").unwrap();
        {
            let mut dl = session.downlink.lock().await;
            dl.max_pending_bytes = 1024;
            assert_eq!(dl.acked, 0);

            let chunk1 = Bytes::from(vec![1u8; 512]);
            dl.chunks.push_back((0, chunk1));
            dl.total = 512;
            assert_eq!(dl.total - dl.acked, 512);

            let chunk2 = Bytes::from(vec![2u8; 512]);
            dl.chunks.push_back((512, chunk2));
            dl.total = 1024;
            assert_eq!(dl.total - dl.acked, 1024);

            assert!(dl.total - dl.acked >= dl.max_pending_bytes as u64);
        }

        let get_resp = download(
            server.state.clone(),
            "bounded-queue-test".into(),
            HeaderMap::new(),
        )
        .await;
        assert_eq!(get_resp.status(), StatusCode::OK);

        let mut body = get_resp.into_body().into_data_stream();
        let first = body.next().await.unwrap().unwrap();
        let second = body.next().await.unwrap().unwrap();
        assert_eq!(first.len(), 512);
        assert_eq!(second.len(), 512);
        assert_eq!(first.as_ref(), &[1u8; 512][..]);
        assert_eq!(second.as_ref(), &[2u8; 512][..]);
    }

    #[tokio::test]
    async fn h1_get_attach_with_large_backlog_does_not_deadlock() {
        let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = echo.accept().await.unwrap();
            let (mut r, mut w) = s.split();
            let _ = tokio::io::copy(&mut r, &mut w).await;
        });

        let server = Server::new(ServerConfig {
            listen: "127.0.0.1:0".into(),
            target: echo_addr.to_string(),
            users: vec![],
            transport: TransportConfig {
                mode: Mode::PacketUp,
                ..Default::default()
            },
            tls: None,
        })
        .unwrap();

        // Fill the store with far more chunks than the old pre-drain channel
        // capacity (16); attaching must never block on channel capacity.
        let session = get_session(&server.state, "backlog-test").unwrap();
        {
            let mut dl = session.downlink.lock().await;
            for index in 0..64u32 {
                let offset = (index * 4096) as u64;
                dl.chunks
                    .push_back((offset, Bytes::from(vec![index as u8; 4096])));
            }
            dl.total = 64 * 4096;
        }

        let response = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            download(
                server.state.clone(),
                "backlog-test".into(),
                HeaderMap::new(),
            ),
        )
        .await
        .expect("download attach must not deadlock with a large backlog");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers().get("x-dl-from").unwrap(), "0");

        let mut body = response.into_body().into_data_stream();
        let mut received = Vec::new();
        while received.len() < 64 * 4096 {
            let chunk = tokio::time::timeout(std::time::Duration::from_secs(2), body.next())
                .await
                .expect("backlog must stream out without deadlock")
                .unwrap()
                .unwrap();
            received.extend_from_slice(&chunk);
        }
        assert_eq!(received.len(), 64 * 4096);
        assert_eq!(received[0], 0);
        assert_eq!(received[4096], 1);
        assert_eq!(received[63 * 4096], 63);
    }

    #[tokio::test]
    async fn h1_get_swap_is_gap_free_and_duplicate_free() {
        let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = echo.accept().await.unwrap();
            let (mut r, mut w) = s.split();
            let _ = tokio::io::copy(&mut r, &mut w).await;
        });

        let server = Server::new(ServerConfig {
            listen: "127.0.0.1:0".into(),
            target: echo_addr.to_string(),
            users: vec![],
            transport: TransportConfig {
                mode: Mode::PacketUp,
                ..Default::default()
            },
            tls: None,
        })
        .unwrap();

        let session = get_session(&server.state, "swap-test").unwrap();

        // partA is buffered before the first GET attaches.
        {
            let mut dl = session.downlink.lock().await;
            dl.chunks.push_back((0, Bytes::from_static(b"partA")));
            dl.total = 5;
        }

        // GET #1 attaches and receives partA from its snapshot.
        let get1 = download(server.state.clone(), "swap-test".into(), HeaderMap::new()).await;
        assert_eq!(get1.headers().get("x-dl-from").unwrap(), "0");
        let mut body1 = get1.into_body().into_data_stream();
        assert_eq!(read_exact_stream(&mut body1, 5).await.as_slice(), b"partA");
        drop(body1); // client-side abort; partA was never acknowledged

        // GET #2 attaches WITHOUT acking partA: unacknowledged bytes are
        // still buffered, so it re-delivers partA and continues with partB.
        {
            let mut dl = session.downlink.lock().await;
            dl.chunks.push_back((5, Bytes::from_static(b"partB")));
            dl.total = 10;
        }
        let get2 = download(server.state.clone(), "swap-test".into(), HeaderMap::new()).await;
        assert_eq!(get2.headers().get("x-dl-from").unwrap(), "0");
        let mut body2 = get2.into_body().into_data_stream();
        assert_eq!(
            read_exact_stream(&mut body2, 10).await.as_slice(),
            b"partApartB"
        );
        drop(body2);

        // GET #3 acknowledges everything produced so far: the server trims
        // the store and the new snapshot starts exactly at the acked offset.
        {
            let mut dl = session.downlink.lock().await;
            dl.chunks.push_back((10, Bytes::from_static(b"partC")));
            dl.total = 15;
        }
        let mut ack_headers = HeaderMap::new();
        ack_headers.insert("x-dl-ack", axum::http::HeaderValue::from_static("10"));
        let get3 = download(server.state.clone(), "swap-test".into(), ack_headers).await;
        assert_eq!(get3.headers().get("x-dl-from").unwrap(), "10");
        let mut body3 = get3.into_body().into_data_stream();
        assert_eq!(read_exact_stream(&mut body3, 5).await.as_slice(), b"partC");
    }

    #[test]
    fn downlink_acknowledge_clamps_and_trims() {
        let mut dl = DownlinkState::new(2 * 1024 * 1024);
        dl.chunks.push_back((0, Bytes::from(vec![0u8; 100])));
        dl.chunks.push_back((100, Bytes::from(vec![1u8; 100])));
        dl.total = 200;

        // Acknowledging past the produced range is clamped.
        dl.acknowledge(500);
        assert_eq!(dl.acked, 200);
        // Both chunks are fully covered and trimmed.
        assert!(dl.chunks.is_empty());

        dl.chunks.push_back((200, Bytes::from(vec![2u8; 10])));
        dl.total = 210;
        // Acknowledgements never regress.
        dl.acknowledge(5);
        assert_eq!(dl.acked, 200);
        assert_eq!(dl.chunks.len(), 1);
    }

    #[tokio::test]
    async fn h1_session_closed_status_header_graceful_shutdown() {
        let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();

        let server = Server::new(ServerConfig {
            listen: "127.0.0.1:0".into(),
            target: echo_addr.to_string(),
            users: vec![],
            transport: TransportConfig {
                mode: Mode::PacketUp,
                h1_enable_session_resumption: true,
                ..Default::default()
            },
            tls: None,
        })
        .unwrap();

        let session = get_session(&server.state, "graceful-close-test").unwrap();
        {
            let mut dl = session.downlink.lock().await;
            dl.backend_closed = true;
        }

        let resp = download(
            server.state.clone(),
            "graceful-close-test".into(),
            HeaderMap::new(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get("x-session-status")
                .and_then(|v| v.to_str().ok()),
            Some("closed")
        );

        let body_bytes = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        assert!(body_bytes.is_empty());
    }
}

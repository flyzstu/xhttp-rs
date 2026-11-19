use crate::{
    config::{ClientConfig, Mode},
    protocol,
};
use anyhow::{Context, Result};
use axum::http::HeaderMap;
use bytes::{Buf, Bytes};
use futures_util::StreamExt;
use reqwest::{Body, Client as HttpClient, Method};
use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, DuplexStream},
    sync::{mpsc, watch},
};
use tokio_util::io::ReaderStream;
use uuid::Uuid;

/// Reassembles offset-tagged downstream segments into a contiguous byte
/// stream.
///
/// Server-side h1 delivery is at-least-once per range: the long-poll GET
/// stream and piggyback POST responses may deliver overlapping ranges and a
/// reconnect may re-deliver unacknowledged bytes. Offset bookkeeping makes
/// that safe: duplicates before the cursor are dropped, brief gaps are
/// buffered until contiguous, and only in-order bytes are written downstream.
#[derive(Default)]
struct DownlinkAssembler {
    /// Contiguous position already written downstream.
    cursor: u64,
    /// Out-of-order segments keyed by start offset.
    pending: BTreeMap<u64, Bytes>,
    pending_bytes: usize,
    /// Set when buffered gap bytes exceeded the sanity cap; the session
    /// should be torn down.
    overflowed: bool,
}

impl DownlinkAssembler {
    /// Sanity cap on buffered out-of-order bytes.
    const MAX_PENDING_BYTES: usize = 4 * 1024 * 1024;

    /// Feed a segment starting at byte offset `from`; returns the newly
    /// contiguous pieces in order.
    fn feed(&mut self, from: u64, mut data: Bytes) -> Vec<Bytes> {
        let mut out = Vec::new();
        let mut pos = from;
        if pos + data.len() as u64 <= self.cursor {
            return out;
        }
        if pos < self.cursor {
            data.advance((self.cursor - pos) as usize);
            pos = self.cursor;
        }
        if !data.is_empty() && pos > self.cursor {
            self.pending_bytes += data.len();
            if self.pending_bytes > Self::MAX_PENDING_BYTES {
                self.overflowed = true;
            }
            self.pending.insert(pos, data);
        } else if !data.is_empty() {
            self.cursor += data.len() as u64;
            out.push(data);
        }
        // Drain segments that have become contiguous.
        while let Some((&start, _)) = self.pending.iter().next() {
            if start < self.cursor {
                let mut bytes = self.pending.remove(&start).expect("key present");
                let end = start + bytes.len() as u64;
                self.pending_bytes -= bytes.len();
                if end <= self.cursor {
                    continue;
                }
                let skip = usize::try_from(self.cursor - start).unwrap_or(0);
                self.pending_bytes = self.pending_bytes.saturating_sub(skip);
                bytes.advance(skip);
                self.pending.insert(self.cursor, bytes);
                continue;
            }
            if start != self.cursor {
                break;
            }
            let bytes = self.pending.remove(&start).expect("key present");
            self.pending_bytes -= bytes.len();
            self.cursor += bytes.len() as u64;
            out.push(bytes);
        }
        out
    }
}

#[derive(Clone)]
pub struct Client {
    config: ClientConfig,
    xmux: Arc<crate::xmux::Manager>,
    request_base: Arc<RequestBase>,
}

struct RequestBase {
    url: url::Url,
    headers: HeaderMap,
}

impl Client {
    pub fn new(mut config: ClientConfig) -> Result<Self> {
        crate::install_crypto_provider();
        config.transport.validate()?;
        let ech_sources = usize::from(config.tls.ech_config.is_some())
            + usize::from(config.tls.ech_config_path.is_some())
            + usize::from(config.tls.ech_config_bytes.is_some());
        if ech_sources > 1 {
            anyhow::bail!("ECH config, config_path and discovered config are mutually exclusive");
        }
        if ech_sources != 0 && !config.server.starts_with("https://") {
            anyhow::bail!("ECH requires HTTPS");
        }
        if ech_sources != 0 && config.tls.insecure {
            anyhow::bail!("ECH cannot be combined with insecure certificate verification");
        }
        let xmux_config = config.transport.xmux.clone();
        let build_config = config.clone();
        let xmux =
            crate::xmux::Manager::new(xmux_config, move || build_http_client(&build_config))?;
        let request_base = Arc::new(build_request_base(&config)?);
        Ok(Self {
            config,
            xmux,
            request_base,
        })
    }
    pub async fn connect(&self) -> Result<DuplexStream> {
        let lease = self.xmux.acquire_connection()?;
        let (application, transport) =
            tokio::io::duplex(self.config.transport.max_packet_size.max(64 * 1024));
        let (read, write) = tokio::io::split(transport);
        let this = self.clone();
        match self.config.transport.mode.resolved() {
            Mode::StreamOne => {
                tokio::spawn(async move {
                    if let Err(error) = this.stream_one(read, write, lease).await {
                        tracing::debug!(%error,"XHTTP stream-one closed");
                    }
                });
            }
            Mode::StreamUp => {
                tokio::spawn(async move {
                    if let Err(error) = this.split_stream(read, write, true, lease).await {
                        tracing::debug!(%error,"XHTTP stream-up closed");
                    }
                });
            }
            Mode::PacketUp | Mode::Auto => {
                tokio::spawn(async move {
                    if let Err(error) = this.split_stream(read, write, false, lease).await {
                        tracing::debug!(?error, "XHTTP packet-up closed");
                    }
                });
            }
        }
        Ok(application)
    }
    pub async fn send(&self, payload: &[u8]) -> Result<Vec<u8>> {
        let mut stream = self.connect().await?;
        stream.write_all(payload).await?;
        stream.shutdown().await?;
        let mut result = Vec::new();
        stream.read_to_end(&mut result).await?;
        Ok(result)
    }
    async fn stream_one(
        &self,
        read: tokio::io::ReadHalf<DuplexStream>,
        mut write: tokio::io::WriteHalf<DuplexStream>,
        lease: crate::xmux::Lease,
    ) -> Result<()> {
        let http = lease.http();
        let (url, mut headers) = self.request(None, None)?;
        if !self.config.transport.no_grpc_header {
            headers.insert("content-type", "application/grpc".parse()?);
        }
        let response = self
            .http_request(&http, Method::POST, url)
            .headers(headers)
            .body(Body::wrap_stream(ReaderStream::new(read)))
            .send()
            .await?
            .error_for_status()?;
        copy_response(response, &mut write).await
    }
    async fn split_stream(
        &self,
        read: tokio::io::ReadHalf<DuplexStream>,
        mut write: tokio::io::WriteHalf<DuplexStream>,
        stream_up: bool,
        mut lease: crate::xmux::Lease,
    ) -> Result<()> {
        let session = Uuid::new_v4().simple().to_string();
        if stream_up {
            let (url, headers) = self.request(Some(&session), None)?;
            let response = self
                .http_request(&lease.http(), Method::GET, url)
                .headers(headers)
                .send()
                .await?
                .error_for_status()?;
            let download = tokio::spawn(async move { copy_response(response, &mut write).await });
            let (url, mut headers) = self.request(Some(&session), None)?;
            if !self.config.transport.no_grpc_header {
                headers.insert("content-type", "application/grpc".parse()?);
            }
            let http = lease.http_for_packet()?;
            self.http_request(&http, self.uplink_method()?, url)
                .headers(headers)
                .body(Body::wrap_stream(ReaderStream::new(read)))
                .send()
                .await?
                .error_for_status()?;
            download.await??;
        } else {
            // packet_up mode. Downlink delivery over h1 is assembled from
            // offset-tagged segments (x-dl-from): GET streams and piggyback
            // POST responses may overlap or repeat, and a reconnect
            // re-delivers unacknowledged bytes. A single assembler owned by
            // the writer task serializes everything into the byte stream.
            let dl_cursor = Arc::new(AtomicU64::new(0));
            let (downlink_tx, mut downlink_rx) = mpsc::channel::<(u64, Bytes)>(64);
            let forward_downlink = {
                let mut write = write;
                let cursor = dl_cursor.clone();
                tokio::spawn(async move {
                    let mut assembler = DownlinkAssembler::default();
                    while let Some((from, chunk)) = downlink_rx.recv().await {
                        for piece in assembler.feed(from, chunk) {
                            if write.write_all(&piece).await.is_err() {
                                return;
                            }
                        }
                        if assembler.overflowed {
                            tracing::error!("h1 downlink assembler overflow; aborting session");
                            return;
                        }
                        cursor.store(assembler.cursor, Ordering::Relaxed);
                    }
                    let _ = write.shutdown().await;
                })
            };

            let this = self.clone();
            let session_clone = session.clone();
            let downlink_tx_get = downlink_tx.clone();
            let http_get = lease.http();
            let enable_resumption = self.config.transport.h1_enable_session_resumption;
            let (cancel_tx, mut cancel_rx) = watch::channel(false);

            let download = tokio::spawn({
                let dl_cursor = dl_cursor.clone();
                async move {
                    'download: loop {
                        let (url, mut headers) = match this.request(Some(&session_clone), None) {
                            Ok(v) => v,
                            Err(_) => break,
                        };
                        headers.insert(
                            "x-dl-ack",
                            axum::http::HeaderValue::from_str(&format!(
                                "{}",
                                dl_cursor.load(Ordering::Relaxed)
                            ))
                            .unwrap_or(axum::http::HeaderValue::from_static("0")),
                        );
                        let response = match this
                            .http_request(&http_get, Method::GET, url)
                            .headers(headers)
                            .send()
                            .await
                        {
                            Ok(r) => match r.error_for_status() {
                                Ok(r) => r,
                                Err(_) => {
                                    if !enable_resumption {
                                        break;
                                    }
                                    tokio::time::sleep(Duration::from_millis(100)).await;
                                    continue;
                                }
                            },
                            Err(_) => {
                                if !enable_resumption {
                                    break;
                                }
                                tokio::time::sleep(Duration::from_millis(100)).await;
                                continue;
                            }
                        };

                        let is_closed = response
                            .headers()
                            .get("x-session-status")
                            .is_some_and(|v| v == "closed");
                        let from = response
                            .headers()
                            .get("x-dl-from")
                            .and_then(|v| v.to_str().ok())
                            .and_then(|v| v.parse::<u64>().ok())
                            .unwrap_or(0);

                        let mut stream = response.bytes_stream();
                        let mut pos = from;
                        let mut got_any = false;
                        loop {
                            tokio::select! {
                                _ = cancel_rx.changed() => break 'download,
                                item = stream.next() => match item {
                                    Some(Ok(bytes)) if !bytes.is_empty() => {
                                        got_any = true;
                                        let len = bytes.len() as u64;
                                        if downlink_tx_get.send((pos, bytes)).await.is_err() {
                                            break 'download;
                                        }
                                        pos += len;
                                    }
                                    Some(Ok(_)) => {}
                                    Some(Err(_)) => break,
                                    None => break,
                                }
                            }
                        }

                        if is_closed || !enable_resumption || downlink_tx_get.is_closed() {
                            break;
                        }
                        if !got_any {
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                }
            });

            let upload_result = self
                .packet_upload(
                    &session,
                    read,
                    &mut lease,
                    downlink_tx.clone(),
                    dl_cursor.clone(),
                )
                .await;
            // A failed upload tears the session down immediately; a graceful
            // upload half-close leaves the GET stream open so trailing
            // downstream data can still be delivered.
            if let Err(error) = upload_result {
                let _ = cancel_tx.send(true);
                drop(downlink_tx);
                let _ = download.await;
                let _ = forward_downlink.await;
                return Err(error);
            }
            drop(downlink_tx);
            let _ = download.await;
            let _ = forward_downlink.await;
        }
        Ok(())
    }
    async fn packet_upload(
        &self,
        session: &str,
        mut read: tokio::io::ReadHalf<DuplexStream>,
        lease: &mut crate::xmux::Lease,
        downlink_tx: mpsc::Sender<(u64, Bytes)>,
        dl_cursor: Arc<AtomicU64>,
    ) -> Result<()> {
        let mut sequence = 0;
        let mut buffer = vec![0; self.config.transport.max_packet_size];
        loop {
            let mut n = read.read(&mut buffer).await?;
            if n == 0 {
                break;
            }
            if self.config.transport.h1_coalesce_delay_ms > 0 && n < 16 * 1024 {
                let delay = Duration::from_millis(self.config.transport.h1_coalesce_delay_ms);
                let deadline = tokio::time::Instant::now() + delay;
                while n < buffer.len() {
                    match tokio::time::timeout_at(deadline, read.read(&mut buffer[n..])).await {
                        Ok(Ok(extra)) if extra > 0 => {
                            n += extra;
                            if n >= 16 * 1024 {
                                break;
                            }
                        }
                        _ => break,
                    }
                }
            }
            let (url, mut headers) = self.request(Some(session), Some(sequence))?;
            if self.config.transport.h1_enable_piggyback {
                headers.insert("x-h1-piggyback", axum::http::HeaderValue::from_static("1"));
            }
            headers.insert(
                "x-dl-ack",
                axum::http::HeaderValue::from_str(&format!(
                    "{}",
                    dl_cursor.load(Ordering::Relaxed)
                ))?,
            );
            let body = protocol::put_payload(&self.config.transport, &buffer[..n], &mut headers)?
                .unwrap_or_default();
            let http = lease.http_for_packet()?;
            let response = self
                .http_request(&http, self.uplink_method()?, url)
                .headers(headers)
                .body(body)
                .send()
                .await?
                .error_for_status()?;

            if self.config.transport.h1_enable_piggyback {
                let from = response
                    .headers()
                    .get("x-dl-from")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(0);
                match response.bytes().await {
                    Ok(piggyback) if !piggyback.is_empty() => {
                        let _ = downlink_tx.send((from, piggyback)).await;
                    }
                    Ok(_) => {}
                    Err(error) => {
                        // The piggybacked bytes stay buffered server-side until
                        // acknowledged, so a failed read here is recoverable by
                        // the next GET attachment.
                        tracing::debug!(%error, "h1 piggyback body read failed");
                    }
                }
            }

            sequence += 1;
            if self.config.transport.packet_interval_ms > 0 {
                tokio::time::sleep(Duration::from_millis(
                    self.config.transport.packet_interval_ms,
                ))
                .await
            }
        }
        Ok(())
    }
    fn request(
        &self,
        session: Option<&str>,
        sequence: Option<u64>,
    ) -> Result<(url::Url, HeaderMap)> {
        let mut url = self.request_base.url.clone();
        let mut headers = self.request_base.headers.clone();
        protocol::apply_padding(&self.config.transport, &mut url, &mut headers);
        protocol::apply_metadata(
            &self.config.transport,
            &mut url,
            &mut headers,
            session,
            sequence,
        )?;
        Ok((url, headers))
    }
    fn uplink_method(&self) -> Result<Method> {
        Method::from_bytes(self.config.transport.uplink_method.as_bytes())
            .context("invalid XHTTP uplink method")
    }
    fn http_request(
        &self,
        http: &HttpClient,
        method: Method,
        url: url::Url,
    ) -> reqwest::RequestBuilder {
        let request = http.request(method, url);
        if self.config.tls.http3 {
            request.version(reqwest::Version::HTTP_3)
        } else {
            request
        }
    }
}

fn build_request_base(config: &ClientConfig) -> Result<RequestBase> {
    let mut url = url::Url::parse(&config.server).context("invalid server URL")?;
    if url.path() == "/" {
        url.set_path(&config.transport.path)
    }
    if !url.path().ends_with('/') {
        let path = format!("{}/", url.path());
        url.set_path(&path);
    }
    if let Some(query) = &config.transport.query {
        for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
            url.query_pairs_mut().append_pair(&key, &value);
        }
    }
    let mut headers = HeaderMap::new();
    protocol::add_common_headers(&config.transport, &mut headers)?;
    if let Some(host) = &config.transport.host {
        headers.insert("host", host.parse()?);
    }
    Ok(RequestBase { url, headers })
}

fn build_http_client(config: &ClientConfig) -> Result<HttpClient> {
    let mut b = HttpClient::builder()
        .connect_timeout(Duration::from_secs(10))
        .pool_idle_timeout(Duration::from_secs(45))
        .pool_max_idle_per_host(8)
        .tcp_keepalive(Duration::from_secs(15));
    if config.transport.xmux.h_keep_alive_period > 0 {
        b = b.tcp_keepalive(Duration::from_secs(
            config.transport.xmux.h_keep_alive_period,
        ));
    }
    if let Some(address) = config.connect_addr {
        let host = url::Url::parse(&config.server)?
            .host_str()
            .context("server URL has no host")?
            .to_owned();
        b = b.resolve(&host, address);
    }
    if config.tls.http3 {
        b = b.http3_prior_knowledge();
    } else if config.tls.http2_only
        || (matches!(config.transport.mode, Mode::StreamOne)
            && config.server.starts_with("http://"))
    {
        b = b.http2_prior_knowledge()
    }

    let ca_pem = match (&config.tls.ca_pem, &config.tls.ca_certificate) {
        (Some(pem), None) => Some(pem.as_bytes().to_vec()),
        (None, Some(path)) => Some(std::fs::read(path).context("read CA certificate")?),
        (None, None) => None,
        (Some(_), Some(_)) => {
            anyhow::bail!("CA PEM and CA certificate path are mutually exclusive")
        }
    };
    let client_certificate = match (
        &config.tls.client_certificate,
        &config.tls.client_certificate_path,
    ) {
        (Some(pem), None) => Some(pem.as_bytes().to_vec()),
        (None, Some(path)) => Some(std::fs::read(path).context("read TLS client certificate")?),
        (None, None) => None,
        (Some(_), Some(_)) => {
            anyhow::bail!("client certificate and client_certificate_path are mutually exclusive")
        }
    };
    let client_key = match (&config.tls.client_key, &config.tls.client_key_path) {
        (Some(pem), None) => Some(pem.as_bytes().to_vec()),
        (None, Some(path)) => Some(std::fs::read(path).context("read TLS client key")?),
        (None, None) => None,
        (Some(_), Some(_)) => {
            anyhow::bail!("client key and client_key_path are mutually exclusive")
        }
    };
    let tls = crate::tls::build_client_config(&crate::tls::ClientOptions {
        insecure: config.tls.insecure,
        include_native_roots: true,
        ca_pem,
        alpn: if config.tls.http3 {
            vec![b"h3".to_vec()]
        } else if config.tls.http2_only {
            vec![b"h2".to_vec()]
        } else {
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        },
        ech_config: load_ech_pem(&config.tls)?,
        certificate_public_key_sha256: crate::tls::decode_public_key_pins(
            &config.tls.certificate_public_key_sha256,
        )?,
        client_certificate,
        client_key,
        disable_sni: config.tls.disable_sni,
        min_version: config
            .tls
            .min_version
            .as_deref()
            .map(crate::tls::parse_tls_version)
            .transpose()?,
        max_version: config
            .tls
            .max_version
            .as_deref()
            .map(crate::tls::parse_tls_version)
            .transpose()?,
    })?;
    b = b.use_preconfigured_tls((*tls).clone());
    b.build().context("build XHTTP HTTP client")
}

fn load_ech_pem(tls: &crate::config::ClientTlsConfig) -> Result<Option<Vec<u8>>> {
    match (&tls.ech_config, &tls.ech_config_path, &tls.ech_config_bytes) {
        (Some(pem), None, None) => Ok(Some(pem.as_bytes().to_vec())),
        (None, Some(path), None) => Ok(Some(std::fs::read(path).context("read ECH config")?)),
        (None, None, Some(bytes)) => Ok(Some(bytes.clone())),
        (None, None, None) => Ok(None),
        _ => anyhow::bail!("ECH config, config_path and discovered config are mutually exclusive"),
    }
}

async fn copy_response(
    response: reqwest::Response,
    write: &mut tokio::io::WriteHalf<DuplexStream>,
) -> Result<()> {
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        write.write_all(&chunk?).await?
    }
    write.shutdown().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TransportConfig;

    #[test]
    fn sing_box_ech_pem_is_accepted() {
        let config = ClientConfig {
            listen: String::new(),
            server: "https://localhost/xhttp".into(),
            connect_addr: None,
            transport: TransportConfig::default(),
            tls: crate::config::ClientTlsConfig {
                ech_config: Some(
                    "-----BEGIN ECH CONFIGS-----\nAET+DQBAAAAgACCT/A3lRXEPEOOFzhZ+AQwpE+z8kKlc2pt8L9tngMF3EwAMAAEAAQABAAIAAQADAAlsb2NhbGhvc3QAAA==\n-----END ECH CONFIGS-----".into(),
                ),
                ..Default::default()
            },
        };
        Client::new(config).unwrap();
    }

    fn assembler_from(segments: &[(u64, &[u8])]) -> (DownlinkAssembler, Vec<Bytes>) {
        let mut assembler = DownlinkAssembler::default();
        let mut out = Vec::new();
        for (from, data) in segments {
            out.extend(assembler.feed(*from, Bytes::copy_from_slice(data)));
        }
        (assembler, out)
    }

    #[test]
    fn assembler_in_order_feed_writes_everything_once() {
        let (assembler, out) = assembler_from(&[(0, b"hello "), (6, b"world")]);
        assert_eq!(
            out.iter().map(|b| b.as_ref()).collect::<Vec<_>>(),
            vec![&b"hello "[..], &b"world"[..]]
        );
        assert_eq!(assembler.cursor, 11);
    }

    #[test]
    fn assembler_out_of_order_gap_is_buffered_then_flushed() {
        let (mut assembler, out) = assembler_from(&[(6, b"world")]);
        assert!(out.is_empty());
        assert_eq!(assembler.cursor, 0);
        assert_eq!(assembler.pending_bytes, 5);

        let out = assembler.feed(0, Bytes::from_static(b"hello "));
        assert_eq!(
            out.iter().map(|b| b.as_ref()).collect::<Vec<_>>(),
            vec![&b"hello "[..], &b"world"[..]]
        );
        assert_eq!(assembler.cursor, 11);
        assert_eq!(assembler.pending_bytes, 0);
    }

    #[test]
    fn assembler_duplicate_prefix_is_dropped() {
        // Server re-delivers "hello world" after a reconnect; the client has
        // already written the first 6 bytes.
        let mut assembler = DownlinkAssembler::default();
        assert_eq!(assembler.feed(0, Bytes::from_static(b"hello ")).len(), 1);
        let out = assembler.feed(0, Bytes::from_static(b"hello world"));
        assert_eq!(
            out.iter().map(|b| b.as_ref()).collect::<Vec<_>>(),
            vec![&b"world"[..]]
        );
        assert_eq!(assembler.cursor, 11);

        // A segment entirely below the cursor produces nothing.
        let out = assembler.feed(0, Bytes::from_static(b"hello "));
        assert!(out.is_empty());
        assert_eq!(assembler.cursor, 11);
    }

    #[test]
    fn assembler_overlapping_gap_segment_is_trimmed_to_cursor() {
        let mut assembler = DownlinkAssembler::default();
        // Gap: 0..8 missing, a later segment is buffered out of order.
        assert!(assembler.feed(8, Bytes::from_static(b"eight!")).is_empty());
        // Filling the gap also flushes the buffered segment.
        let out = assembler.feed(0, Bytes::from_static(b"01234567"));
        assert_eq!(
            out.iter().map(|b| b.as_ref()).collect::<Vec<_>>(),
            vec![&b"01234567"[..], &b"eight!"[..]]
        );
        assert_eq!(assembler.cursor, 14);

        // A re-delivery straddling the cursor (10..20 vs cursor 14) is
        // trimmed to its unacknowledged tail.
        let out = assembler.feed(10, Bytes::from_static(b"0123456789"));
        assert_eq!(
            out.iter().map(|b| b.as_ref()).collect::<Vec<_>>(),
            vec![&b"456789"[..]]
        );
        assert_eq!(assembler.cursor, 20);

        // A segment entirely below the cursor produces nothing.
        let out = assembler.feed(4, Bytes::from_static(b"45678901"));
        assert!(out.is_empty());
        assert_eq!(assembler.cursor, 20);
    }
}

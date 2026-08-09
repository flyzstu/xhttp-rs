use crate::{
    config::{ClientConfig, Mode},
    protocol,
};
use anyhow::{Context, Result};
use axum::http::HeaderMap;
use futures_util::StreamExt;
use reqwest::{Body, Client as HttpClient, Method};
use std::{sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio_util::io::ReaderStream;
use uuid::Uuid;

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
        let (url, headers) = self.request(Some(&session), None)?;
        let response = self
            .http_request(&lease.http(), Method::GET, url)
            .headers(headers)
            .send()
            .await?
            .error_for_status()?;
        let download = tokio::spawn(async move { copy_response(response, &mut write).await });
        if stream_up {
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
        } else {
            self.packet_upload(&session, read, &mut lease).await?;
        }
        download.await??;
        Ok(())
    }
    async fn packet_upload(
        &self,
        session: &str,
        mut read: tokio::io::ReadHalf<DuplexStream>,
        lease: &mut crate::xmux::Lease,
    ) -> Result<()> {
        let mut sequence = 0;
        let mut buffer = vec![0; self.config.transport.max_packet_size];
        loop {
            let n = read.read(&mut buffer).await?;
            if n == 0 {
                break;
            }
            let (url, mut headers) = self.request(Some(session), Some(sequence))?;
            let body = protocol::put_payload(&self.config.transport, &buffer[..n], &mut headers)?
                .unwrap_or_default();
            let http = lease.http_for_packet()?;
            self.http_request(&http, self.uplink_method()?, url)
                .headers(headers)
                .body(body)
                .send()
                .await?
                .error_for_status()?;
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
        .pool_idle_timeout(Duration::from_secs(300));
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
}

use crate::{
    config::{ClientConfig, Mode},
    protocol,
};
use anyhow::{Context, Result};
use axum::http::HeaderMap;
use futures_util::StreamExt;
use reqwest::{Body, Client as HttpClient, Method};
use rustls::pki_types::{EchConfigListBytes, pem::PemObject};
use std::{sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio_util::io::ReaderStream;
use uuid::Uuid;

#[derive(Clone)]
pub struct Client {
    config: ClientConfig,
    xmux: Arc<crate::xmux::Manager>,
}
impl Client {
    pub fn new(mut config: ClientConfig) -> Result<Self> {
        crate::install_crypto_provider();
        config.transport.validate()?;
        if config.tls.ech_config.is_some() && config.tls.ech_config_path.is_some() {
            anyhow::bail!("ECH config and config_path are mutually exclusive");
        }
        if (config.tls.ech_config.is_some() || config.tls.ech_config_path.is_some())
            && !config.server.starts_with("https://")
        {
            anyhow::bail!("ECH requires HTTPS");
        }
        if (config.tls.ech_config.is_some() || config.tls.ech_config_path.is_some())
            && config.tls.insecure
        {
            anyhow::bail!("ECH cannot be combined with insecure certificate verification");
        }
        let xmux_config = config.transport.xmux.clone();
        let build_config = config.clone();
        let xmux =
            crate::xmux::Manager::new(xmux_config, move || build_http_client(&build_config))?;
        Ok(Self { config, xmux })
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
        let mut url = url::Url::parse(&self.config.server).context("invalid server URL")?;
        if url.path() == "/" {
            url.set_path(&self.config.transport.path)
        }
        if !url.path().ends_with('/') {
            let path = format!("{}/", url.path());
            url.set_path(&path);
        }
        if let Some(query) = &self.config.transport.query {
            for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
                url.query_pairs_mut().append_pair(&key, &value);
            }
        }
        let mut headers = HeaderMap::new();
        protocol::add_common_headers(&self.config.transport, &mut headers)?;
        protocol::apply_padding(&self.config.transport, &mut url, &mut headers);
        protocol::apply_metadata(
            &self.config.transport,
            &mut url,
            &mut headers,
            session,
            sequence,
        )?;
        if let Some(host) = &self.config.transport.host {
            headers.insert("host", host.parse()?);
        }
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

fn build_http_client(config: &ClientConfig) -> Result<HttpClient> {
    let mut b = HttpClient::builder()
        .danger_accept_invalid_certs(config.tls.insecure)
        .connect_timeout(Duration::from_secs(10))
        .pool_idle_timeout(Duration::from_secs(300));
    if config.transport.xmux.h_keep_alive_period > 0 {
        b = b.tcp_keepalive(Duration::from_secs(
            config.transport.xmux.h_keep_alive_period,
        ));
    }
    if let Some(path) = &config.tls.ca_certificate {
        let pem = std::fs::read(path).context("read CA certificate")?;
        b = b.add_root_certificate(reqwest::Certificate::from_pem(&pem)?)
    } else if let Some(pem) = &config.tls.ca_pem {
        b = b.add_root_certificate(reqwest::Certificate::from_pem(pem.as_bytes())?)
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

    let ech_pem = load_ech_pem(&config.tls)?;
    if let Some(ech_pem) = ech_pem {
        let ech = parse_ech_config(&ech_pem)?;
        let mut roots = rustls::RootCertStore::empty();
        let native = rustls_native_certs::load_native_certs();
        for cert in native.certs {
            roots.add(cert).context("add native root certificate")?;
        }
        if let Some(path) = &config.tls.ca_certificate {
            add_ca_pem(
                &mut roots,
                &std::fs::read(path).context("read CA certificate")?,
            )?;
        } else if let Some(pem) = &config.tls.ca_pem {
            add_ca_pem(&mut roots, pem.as_bytes())?;
        }
        let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_ech(rustls::client::EchMode::Enable(ech))?
        .with_root_certificates(roots)
        .with_no_client_auth();
        tls.alpn_protocols = if config.tls.http3 {
            vec![b"h3".to_vec()]
        } else if config.tls.http2_only {
            vec![b"h2".to_vec()]
        } else {
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        };
        b = b.use_preconfigured_tls(tls);
    }
    b.build().context("build XHTTP HTTP client")
}

fn load_ech_pem(tls: &crate::config::ClientTlsConfig) -> Result<Option<Vec<u8>>> {
    match (&tls.ech_config, &tls.ech_config_path) {
        (Some(pem), None) => Ok(Some(pem.as_bytes().to_vec())),
        (None, Some(path)) => Ok(Some(std::fs::read(path).context("read ECH config")?)),
        (None, None) => Ok(None),
        (Some(_), Some(_)) => anyhow::bail!("ECH config and config_path are mutually exclusive"),
    }
}

pub(crate) fn parse_ech_config(pem: &[u8]) -> Result<rustls::client::EchConfig> {
    let pem = normalize_ech_pem(pem);
    let bytes = EchConfigListBytes::from_pem_slice(&pem).context("parse ECH config PEM")?;
    rustls::client::EchConfig::new(bytes, rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES)
        .context("select supported ECH config")
}

fn normalize_ech_pem(pem: &[u8]) -> Vec<u8> {
    String::from_utf8_lossy(pem)
        .replace("BEGIN ECH CONFIGS", "BEGIN ECHCONFIG")
        .replace("END ECH CONFIGS", "END ECHCONFIG")
        .into_bytes()
}

fn add_ca_pem(roots: &mut rustls::RootCertStore, pem: &[u8]) -> Result<()> {
    let mut reader = std::io::Cursor::new(pem);
    for cert in rustls_pemfile::certs(&mut reader) {
        roots.add(cert?).context("add custom CA certificate")?;
    }
    Ok(())
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

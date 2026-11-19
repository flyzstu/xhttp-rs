use crate::{dns::DnsResolver, vless};
use anyhow::{Context, Result, bail};
use std::{collections::HashMap, sync::Arc};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use url::Url;

use super::outbound::{Dialer, resolve_grouped_dialer};
use super::udp;

/// Resolves outbound tags to tunneled connections for `detour` DNS servers.
/// Follows selector/urltest groups to their current member, then opens a UDP
/// session (XUDP for VLESS, UoT for AnyTLS, a plain socket for direct) or a
/// TCP stream through that outbound.
pub(crate) struct DetourProvider {
    dialers: Arc<HashMap<String, Dialer>>,
    resolver: Option<Arc<DnsResolver>>,
}

impl DetourProvider {
    pub(crate) fn new(
        dialers: Arc<HashMap<String, Dialer>>,
        resolver: Option<Arc<DnsResolver>>,
    ) -> Self {
        Self { dialers, resolver }
    }

    fn resolve(&self, tag: &str) -> Option<Dialer> {
        resolve_grouped_dialer(&self.dialers, tag)
    }

    /// Resolve a dialer by tag for external use (e.g. warm-up before
    /// rule-set prefetch).
    pub(crate) fn dialer(&self, tag: &str) -> Option<Dialer> {
        self.resolve(tag)
    }
}

impl crate::dns::transport::DnsUdpDetour for DetourProvider {
    fn exchange_udp(
        &self,
        tag: &str,
        destination: std::net::SocketAddr,
        request: &[u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>>> + Send + '_>> {
        let tag = tag.to_owned();
        let request = request.to_vec();
        Box::pin(async move { self.exchange_udp_inner(&tag, destination, &request).await })
    }

    fn connect_tcp(
        &self,
        tag: &str,
        destination: std::net::SocketAddr,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<Box<dyn crate::dns::transport::DnsIo>>>
                + Send
                + '_,
        >,
    > {
        let tag = tag.to_owned();
        Box::pin(async move { self.connect_tcp_inner(&tag, destination).await })
    }
}

impl DetourProvider {
    async fn exchange_udp_inner(
        &self,
        tag: &str,
        destination: std::net::SocketAddr,
        request: &[u8],
    ) -> Result<Vec<u8>> {
        let dialer = self
            .resolve(tag)
            .with_context(|| format!("unknown DNS detour outbound: {tag}"))?;
        match dialer {
            Dialer::Direct => {
                let socket = super::direct::direct_udp_socket(destination, &Default::default())?;
                socket.connect(destination).await?;
                socket.send(request).await?;
                let mut response = vec![0; u16::MAX as usize];
                let length = tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    socket.recv(&mut response),
                )
                .await
                .context("DNS detour direct timeout")??;
                response.truncate(length);
                Ok(response)
            }
            Dialer::Vless { client, user, xudp } => {
                let destination = vless::Destination::Ip(destination.ip(), destination.port());
                let mut stream = client.connect().await?;
                vless::write_request_with_command(
                    &mut stream,
                    &user,
                    if xudp {
                        vless::Command::Xudp
                    } else {
                        vless::Command::Udp
                    },
                    &destination,
                )
                .await?;
                if xudp {
                    vless::write_xudp_packet(&mut stream, true, &destination, request).await?;
                } else {
                    stream
                        .write_u16(request.len().try_into().context("DNS query too large")?)
                        .await?;
                    stream.write_all(request).await?;
                    stream.flush().await?;
                }
                vless::read_response(&mut stream).await?;
                let response = if xudp {
                    let (_, payload) = vless::read_xudp_packet(&mut stream).await?;
                    payload
                } else {
                    let length = stream.read_u16().await? as usize;
                    let mut response = vec![0; length];
                    stream.read_exact(&mut response).await?;
                    response
                };
                Ok(response)
            }
            Dialer::AnyTls { client } => {
                let destination = udp::to_anytls_destination(&vless::Destination::Ip(
                    destination.ip(),
                    destination.port(),
                ));
                let initial = anytls::encode_address(&anytls::uot::magic_destination())?;
                let mut stream = client.create_stream(&initial).await?;
                anytls::uot::write_request(
                    &mut stream,
                    &anytls::uot::Request {
                        is_connect: true,
                        destination: destination.clone(),
                    },
                )
                .await?;
                anytls::uot::write_packet(&mut stream, &destination, request, true).await?;
                let (_, payload) =
                    anytls::uot::read_packet(&mut stream, Some(&destination)).await?;
                Ok(payload)
            }
            Dialer::Block | Dialer::Group(_) => bail!("DNS detour cannot use block/group outbound"),
        }
    }

    async fn connect_tcp_inner(
        &self,
        tag: &str,
        destination: std::net::SocketAddr,
    ) -> Result<Box<dyn crate::dns::transport::DnsIo>> {
        self.connect_tcp_destination(
            tag,
            &vless::Destination::Ip(destination.ip(), destination.port()),
        )
        .await
    }

    async fn resolve_destination(&self, destination: &vless::Destination) -> vless::Destination {
        let (host, port) = match destination {
            vless::Destination::Domain(host, port) => (host, *port),
            vless::Destination::Ip(..) => return destination.clone(),
        };
        if let Some(resolver) = &self.resolver
            && let Ok(Ok(ips)) =
                tokio::time::timeout(std::time::Duration::from_secs(3), resolver.lookup(host)).await
            && let Some(ip) = ips
                .iter()
                .find(|ip| ip.is_ipv4())
                .copied()
                .or_else(|| ips.first().copied())
        {
            tracing::debug!(host, resolved = %ip, "resolved domain destination to IP for detour outbound");
            return vless::Destination::Ip(ip, port);
        }
        if let Ok(Ok(mut addrs)) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            tokio::net::lookup_host((host.as_str(), port)),
        )
        .await
        {
            let ips: Vec<_> = addrs.by_ref().map(|a| a.ip()).collect();
            if let Some(ip) = ips
                .iter()
                .find(|ip| ip.is_ipv4())
                .copied()
                .or_else(|| ips.first().copied())
            {
                tracing::debug!(host, resolved = %ip, "fallback resolved domain destination to IP for detour outbound");
                return vless::Destination::Ip(ip, port);
            }
        }
        destination.clone()
    }

    async fn connect_tcp_destination(
        &self,
        tag: &str,
        destination: &vless::Destination,
    ) -> Result<Box<dyn crate::dns::transport::DnsIo>> {
        let dialer = self
            .resolve(tag)
            .with_context(|| format!("unknown detour outbound: {tag}"))?;
        let resolved = self.resolve_destination(destination).await;
        match dialer {
            Dialer::Direct => Ok(Box::new(
                super::direct::connect_direct(
                    &resolved,
                    self.resolver.as_deref(),
                    &Default::default(),
                    &[],
                )
                .await?,
            )),
            Dialer::Vless { client, user, .. } => {
                let mut stream = client.connect().await?;
                vless::write_request(&mut stream, &user, &resolved).await?;
                vless::read_response(&mut stream).await?;
                Ok(Box::new(stream))
            }
            Dialer::AnyTls { client } => {
                let anytls_dest = udp::to_anytls_destination(&resolved);
                let stream = client
                    .create_stream(&anytls::encode_address(&anytls_dest)?)
                    .await?;
                Ok(Box::new(stream))
            }
            Dialer::Block | Dialer::Group(_) => bail!("detour cannot use block/group outbound"),
        }
    }

    /// Fetch a URL over HTTP/1.1 through the outbound `tag`. HTTPS URLs are
    /// wrapped in TLS with native roots; redirects are followed up to five
    /// hops; the body is limited to 64 MiB.
    pub(crate) async fn fetch_url(&self, tag: &str, url: &str) -> Result<Vec<u8>> {
        self.fetch_url_inner(tag, url, 0).await
    }

    /// Fetch a URL with conditional request support: `etag` is sent as
    /// `If-None-Match`, and a 304 response yields `(empty, etag, true)`.
    pub(crate) async fn fetch_url_etag(
        &self,
        tag: &str,
        url: &str,
        etag: Option<&str>,
    ) -> Result<(Vec<u8>, Option<String>, bool)> {
        let (data, headers, status) = self.fetch_url_with_etag(tag, url, etag, 0).await?;
        let new_etag = headers
            .iter()
            .find_map(|(name, value)| name.eq_ignore_ascii_case("etag").then(|| value.clone()));
        Ok((data, new_etag, status == 304))
    }

    async fn fetch_url_with_etag(
        &self,
        tag: &str,
        url: &str,
        etag: Option<&str>,
        redirects: u8,
    ) -> Result<(Vec<u8>, Vec<(String, String)>, u16)> {
        if redirects > 5 {
            bail!("HTTP redirect limit exceeded for {url}")
        }
        let url = Url::parse(url).context("invalid rule-set URL")?;
        let scheme = url.scheme();
        if !matches!(scheme, "http" | "https") {
            bail!("unsupported rule-set URL scheme: {scheme}")
        }
        let host = url
            .host_str()
            .context("rule-set URL has no host")?
            .to_owned();
        let port = url
            .port_or_known_default()
            .context("rule-set URL has no port")?;
        let path = if url.path().is_empty() {
            "/".to_owned()
        } else {
            url.path().to_owned()
        };
        let query = url
            .query()
            .map(|query| format!("?{query}"))
            .unwrap_or_default();
        let destination = if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            vless::Destination::Ip(ip, port)
        } else {
            vless::Destination::Domain(host.clone(), port)
        };
        let tcp = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            self.connect_tcp_destination(tag, &destination),
        )
        .await
        .map_err(|_| {
            anyhow::anyhow!("connect rule-set host {host}:{port} through outbound {tag} timed out")
        })?
        .with_context(|| format!("connect rule-set host {host}:{port} through outbound {tag}"))?;

        let mut stream: Box<dyn crate::dns::transport::DnsIo> = if scheme == "https" {
            let mut roots = rustls::RootCertStore::empty();
            for certificate in rustls_native_certs::load_native_certs().certs {
                roots
                    .add(certificate)
                    .context("add native root certificate")?;
            }
            let connector = tokio_rustls::TlsConnector::from(Arc::new(
                rustls::ClientConfig::builder()
                    .with_root_certificates(roots)
                    .with_no_client_auth(),
            ));
            let name = rustls::pki_types::ServerName::try_from(host.clone())
                .context("invalid rule-set host")?;
            let tls_stream = tokio::time::timeout(
                std::time::Duration::from_secs(10),
                connector.connect(name, tcp),
            )
            .await
            .map_err(|_| anyhow::anyhow!("TLS handshake with {host}:{port} timed out"))?
            .with_context(|| format!("TLS handshake with {host}:{port}"))?;
            Box::new(tls_stream)
        } else {
            tcp
        };
        let conditional = etag
            .filter(|value| !value.is_empty())
            .map(|value| format!("If-None-Match: {value}\r\n"))
            .unwrap_or_default();
        let request = format!(
            "GET {path}{query} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: sing-box/1.10.0 (xhttp-rs)\r\nConnection: close\r\nAccept: */*\r\n{conditional}\r\n"
        );
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            stream.write_all(request.as_bytes()).await?;
            stream.flush().await
        })
        .await
        .map_err(|_| anyhow::anyhow!("send HTTP request timed out"))??;

        let response = tokio::time::timeout(
            std::time::Duration::from_secs(15),
            read_http_response(&mut *stream),
        )
        .await
        .map_err(|_| anyhow::anyhow!("read HTTP response timed out"))??;
        let (status, headers, body) = response;
        if matches!(status, 301 | 302 | 303 | 307 | 308) {
            let location = headers
                .iter()
                .find_map(|(name, value)| {
                    name.eq_ignore_ascii_case("location").then(|| value.clone())
                })
                .context("redirect response has no Location header")?;
            let next = url
                .join(&location)
                .context("invalid redirect Location")?
                .to_string();
            return Box::pin(self.fetch_url_with_etag(tag, &next, etag, redirects + 1)).await;
        }
        if status != 200 && status != 304 {
            bail!("rule-set download returned HTTP {status}")
        }
        if body.len() > 64 * 1024 * 1024 {
            bail!("rule-set download exceeds 64 MiB")
        }
        Ok((body, headers, status))
    }

    async fn fetch_url_inner(&self, tag: &str, url: &str, redirects: u8) -> Result<Vec<u8>> {
        let (body, _, status) = self.fetch_url_with_etag(tag, url, None, redirects).await?;
        if status == 304 {
            bail!("unexpected 304 response without a conditional request")
        }
        Ok(body)
    }
}

/// Read an HTTP/1.1 response: status line, headers, and body. Handles
/// `Content-Length`, chunked transfer encoding, and close-delimited bodies.
async fn read_http_response(
    stream: &mut dyn crate::dns::transport::DnsIo,
) -> Result<(u16, Vec<(String, String)>, Vec<u8>)> {
    use tokio::io::AsyncBufReadExt;
    let mut reader = tokio::io::BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).await?;
    let mut parts = line.split_whitespace();
    let _version = parts.next().context("missing HTTP version")?;
    let status: u16 = parts
        .next()
        .context("missing HTTP status")?
        .parse()
        .context("invalid HTTP status")?;
    let mut headers = Vec::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        let line = line.trim_end_matches("\r\n");
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_owned(), value.trim().to_owned()));
        }
    }
    let content_length = headers.iter().find_map(|(name, value)| {
        name.eq_ignore_ascii_case("content-length")
            .then(|| value.parse::<usize>().ok())
            .flatten()
    });
    let chunked = headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("transfer-encoding")
            && value.to_ascii_lowercase().contains("chunked")
    });
    let mut body = Vec::new();
    if let Some(length) = content_length {
        body.reserve(length);
        reader.take(length as u64).read_to_end(&mut body).await?;
    } else if chunked {
        loop {
            let mut size_line = String::new();
            reader.read_line(&mut size_line).await?;
            let size = usize::from_str_radix(size_line.trim().trim_end_matches(";"), 16)
                .context("invalid chunk size")?;
            if size == 0 {
                let mut trailer = Vec::new();
                reader.read_until(b'\n', &mut trailer).await?;
                reader.read_until(b'\n', &mut trailer).await?;
                break;
            }
            let start = body.len();
            body.resize(start + size, 0);
            reader.read_exact(&mut body[start..]).await?;
            let mut crlf = [0u8; 2];
            reader.read_exact(&mut crlf).await?;
        }
    } else {
        reader.read_to_end(&mut body).await?;
    }
    Ok((status, headers, body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::io::AsyncWriteExt;

    fn io_box(stream: tokio::io::DuplexStream) -> Box<dyn crate::dns::transport::DnsIo> {
        Box::new(stream)
    }

    #[tokio::test]
    async fn http_response_parser_handles_content_length() {
        let (client, mut server) = tokio::io::duplex(1024);
        tokio::spawn(async move {
            server
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
                .await
                .unwrap();
        });
        let mut stream = io_box(client);
        let (status, headers, body) = read_http_response(&mut *stream).await.unwrap();
        assert_eq!(status, 200);
        assert!(
            headers
                .iter()
                .any(|(name, value)| name.eq_ignore_ascii_case("content-length") && value == "5")
        );
        assert_eq!(body, b"hello");
    }

    #[tokio::test]
    async fn http_response_parser_handles_chunked_encoding() {
        let (client, mut server) = tokio::io::duplex(1024);
        tokio::spawn(async move {
            server
                .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n")
                .await
                .unwrap();
        });
        let mut stream = io_box(client);
        let (status, _, body) = read_http_response(&mut *stream).await.unwrap();
        assert_eq!(status, 200);
        assert_eq!(body, b"hello world");
    }

    #[tokio::test]
    async fn http_response_parser_handles_close_delimited_body() {
        let (client, mut server) = tokio::io::duplex(1024);
        tokio::spawn(async move {
            server
                .write_all(b"HTTP/1.1 200 OK\r\n\r\nbody until close")
                .await
                .unwrap();
            server.shutdown().await.unwrap();
        });
        let mut stream = io_box(client);
        let (status, _, body) = read_http_response(&mut *stream).await.unwrap();
        assert_eq!(status, 200);
        assert_eq!(body, b"body until close");
    }

    #[tokio::test]
    async fn fetch_url_etag_returns_body_then_not_modified() {
        use tokio::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = vec![0; 4096];
            let _ = stream.read(&mut request).await.unwrap();
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nETag: \"v1\"\r\n\r\nhello")
                .await
                .unwrap();
        });
        let mut dialers = HashMap::new();
        dialers.insert("direct".into(), Dialer::Direct);
        let provider = DetourProvider::new(Arc::new(dialers), None);
        let url = format!("http://{address}/rules.json");
        let (body, etag, not_modified) =
            provider.fetch_url_etag("direct", &url, None).await.unwrap();
        assert_eq!(body, b"hello");
        assert_eq!(etag.as_deref(), Some("\"v1\""));
        assert!(!not_modified);

        // Second request with the etag gets 304 from a conditional server.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = vec![0; 4096];
            let _ = stream.read(&mut request).await.unwrap();
            stream
                .write_all(b"HTTP/1.1 304 Not Modified\r\nETag: \"v1\"\r\n\r\n")
                .await
                .unwrap();
        });
        let (body, etag, not_modified) = provider
            .fetch_url_etag(
                "direct",
                &format!("http://{address}/rules.json"),
                Some("\"v1\""),
            )
            .await
            .unwrap();
        assert!(body.is_empty());
        assert_eq!(etag.as_deref(), Some("\"v1\""));
        assert!(not_modified);
    }

    #[tokio::test]
    async fn fetch_url_etag_follows_redirects() {
        use tokio::net::TcpListener;
        let first = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let second = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let first_addr = first.local_addr().unwrap();
        let second_addr = second.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = first.accept().await.unwrap();
            let mut request = vec![0; 4096];
            let _ = stream.read(&mut request).await.unwrap();
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 302 Found\r\nLocation: http://{second_addr}/final\r\nContent-Length: 0\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
        });
        tokio::spawn(async move {
            let (mut stream, _) = second.accept().await.unwrap();
            let mut request = vec![0; 4096];
            let _ = stream.read(&mut request).await.unwrap();
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nfinal!")
                .await
                .unwrap();
        });
        let mut dialers = HashMap::new();
        dialers.insert("direct".into(), Dialer::Direct);
        let provider = DetourProvider::new(Arc::new(dialers), None);
        let (body, _, not_modified) = provider
            .fetch_url_etag("direct", &format!("http://{first_addr}/start"), None)
            .await
            .unwrap();
        assert_eq!(body, b"final!");
        assert!(!not_modified);
    }
}

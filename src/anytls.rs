use crate::singbox::{DnsConfig, Inbound, Outbound, RouteConfig, TlsConfig};
use anyhow::{Context, Result, bail};
use anytls::{ClientOptions, Connector, SessionConfig, client_authentication};
use rustls::{
    DigitallySignedStruct, DistinguishedName, SignatureScheme,
    pki_types::{CertificateDer, ServerName, UnixTime},
    server::danger::{ClientCertVerified, ClientCertVerifier},
};
use sha2::{Digest, Sha256};
use std::{sync::Arc, time::Duration};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::RwLock,
};
use tokio_rustls::{TlsAcceptor, TlsConnector};

pub async fn run_inbound(
    inbound: Inbound,
    outbounds: Vec<Outbound>,
    route: Option<RouteConfig>,
    dns: Option<DnsConfig>,
    http_clients: Vec<crate::singbox::HttpClientConfig>,
    dns_cache_path: Option<std::path::PathBuf>,
) -> Result<()> {
    let runtime = Arc::new(
        crate::proxy::build_runtime(outbounds, route, dns, http_clients, dns_cache_path).await?,
    );
    let listen = socket(
        inbound.listen.as_deref().unwrap_or("::"),
        inbound
            .listen_port
            .context("AnyTLS inbound requires listen_port")?,
    );
    let listener = TcpListener::bind(&listen).await?;
    let tls = match inbound.tls.as_ref().filter(|tls| tls.enabled) {
        Some(tls) => Some(build_server_tls(tls)?),
        None => None,
    };
    let users = Arc::new(
        inbound
            .users
            .iter()
            .map(|user| anytls::UserCredential {
                name: user.name.clone().unwrap_or_default(),
                password: user.password.clone().unwrap_or_default(),
            })
            .collect::<Vec<_>>(),
    );
    let padding = if inbound.padding_scheme.is_empty() {
        anytls::PaddingScheme::default()
    } else {
        anytls::PaddingScheme::parse(inbound.padding_scheme.join("\n").as_bytes())?
    };
    let padding = Arc::new(RwLock::new(padding));
    let inbound_tag: Arc<str> = inbound
        .tag
        .clone()
        .unwrap_or_else(|| "anytls-in".into())
        .into();
    loop {
        let (socket, source) = listener.accept().await?;
        configure_tcp(&socket).context("enable TCP_NODELAY on AnyTLS inbound")?;
        let tls = tls.clone();
        let users = users.clone();
        let padding = padding.clone();
        let runtime = runtime.clone();
        let inbound_tag = inbound_tag.clone();
        tokio::spawn(async move {
            let result: Result<()> = async {
                let local_addr = socket.local_addr().ok();
                let mut transport: anytls::BoxedIo = match tls {
                    Some(tls) => Box::new(
                        tls.accept(socket)
                            .await
                            .context("AnyTLS TLS handshake")?,
                    ),
                    None => Box::new(socket),
                };
                let user = anytls::authenticate_users(&mut transport, &users)
                    .await
                    .context("AnyTLS authentication")?;
                let mut session = anytls::ServerSession::new(
                    transport,
                    SessionConfig {
                        padding,
                        implementation: format!("xhttp-rs/{}", env!("CARGO_PKG_VERSION")),
                        local_addr,
                        remote_addr: Some(source),
                        ..SessionConfig::default()
                    },
                );
                while let Some(incoming) = session.accept().await {
                    let runtime = runtime.clone();
                    let inbound_tag = inbound_tag.clone();
                    let user = user.clone();
                    tokio::spawn(async move {
                        let mut stream = incoming.stream;
                        let result: Result<()> = async {
                            let destination = anytls::read_address(&mut stream).await?;
                            if matches!(&destination, anytls::Address::Domain(domain, _) if domain == anytls::uot::MAGIC_ADDRESS)
                            {
                                let request = anytls::uot::read_request(&mut stream).await?;
                                crate::proxy::relay_anytls_udp(
                                    stream,
                                    request,
                                    source,
                                    &inbound_tag,
                                    (!user.is_empty()).then_some(user.as_str()),
                                    &runtime,
                                )
                                .await
                            } else {
                                crate::proxy::relay_anytls_tcp(
                                    stream,
                                    destination,
                                    source,
                                    &inbound_tag,
                                    (!user.is_empty()).then_some(user.as_str()),
                                    &runtime,
                                )
                                .await
                            }
                        }
                        .await;
                        if let Err(error) = result {
                            tracing::debug!(%source, %error, "AnyTLS stream closed");
                        }
                    });
                }
                Ok(())
            }
            .await;
            if let Err(error) = result {
                tracing::debug!(%source, %error, "AnyTLS connection closed");
            }
        });
    }
}

fn build_server_tls(tls: &TlsConfig) -> Result<TlsAcceptor> {
    crate::install_crypto_provider();
    let certificate = load_required_material(
        &tls.certificate,
        tls.certificate_path.as_deref(),
        "AnyTLS TLS certificate",
    )?;
    let key = load_required_material(&tls.key, tls.key_path.as_deref(), "AnyTLS TLS private key")?;
    let certificates = rustls_pemfile::certs(&mut std::io::Cursor::new(certificate))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let private_key = rustls_pemfile::private_key(&mut std::io::Cursor::new(key))?
        .context("AnyTLS TLS private key is missing")?;
    let verifier = rustls_client_verifier(tls)?;
    let mut config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certificates, private_key)?;
    config.alpn_protocols = tls
        .alpn
        .iter()
        .map(|value| value.as_bytes().to_vec())
        .collect();
    Ok(TlsAcceptor::from(Arc::new(config)))
}

pub(crate) fn validate_server_tls(tls: &TlsConfig) -> Result<()> {
    build_server_tls(tls).map(drop)
}

fn load_required_material(inline: &[String], path: Option<&str>, name: &str) -> Result<Vec<u8>> {
    crate::tls::load_optional_material(inline, path, name)?
        .with_context(|| format!("{name} is missing"))
}

fn effective_client_authentication(tls: &TlsConfig) -> &str {
    tls.client_authentication.as_deref().unwrap_or_else(|| {
        if tls.client_certificate.is_empty()
            && tls.client_certificate_path.is_none()
            && tls.client_certificate_public_key_sha256.is_empty()
        {
            "no"
        } else {
            "require-and-verify"
        }
    })
}

fn rustls_client_verifier(tls: &TlsConfig) -> Result<Arc<dyn ClientCertVerifier>> {
    let authentication = effective_client_authentication(tls);
    let pins = crate::tls::decode_public_key_pins(&tls.client_certificate_public_key_sha256)?;
    match authentication {
        "no" => Ok(rustls::server::WebPkiClientVerifier::no_client_auth()),
        "request" | "require-any" => Ok(Arc::new(DirectClientVerifier::new(
            authentication == "require-any",
            Vec::new(),
        ))),
        "verify-if-given" | "require-and-verify" if !pins.is_empty() => Ok(Arc::new(
            DirectClientVerifier::new(authentication == "require-and-verify", pins),
        )),
        "verify-if-given" | "require-and-verify" => {
            let pem = load_required_material(
                &tls.client_certificate,
                tls.client_certificate_path.as_deref(),
                "AnyTLS client CA certificate",
            )?;
            let mut roots = rustls::RootCertStore::empty();
            for certificate in rustls_pemfile::certs(&mut std::io::Cursor::new(pem)) {
                roots.add(certificate?)?;
            }
            if roots.is_empty() {
                bail!("AnyTLS client CA certificate input contains no certificates")
            }
            let builder = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots));
            if authentication == "verify-if-given" {
                Ok(builder.allow_unauthenticated().build()?)
            } else {
                Ok(builder.build()?)
            }
        }
        value => bail!("unknown client_authentication: {value}"),
    }
}

#[derive(Debug)]
struct DirectClientVerifier {
    mandatory: bool,
    pins: Vec<[u8; 32]>,
    algorithms: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl DirectClientVerifier {
    fn new(mandatory: bool, pins: Vec<[u8; 32]>) -> Self {
        Self {
            mandatory,
            pins,
            algorithms: rustls::crypto::aws_lc_rs::default_provider()
                .signature_verification_algorithms,
        }
    }
}

impl ClientCertVerifier for DirectClientVerifier {
    fn client_auth_mandatory(&self) -> bool {
        self.mandatory
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> std::result::Result<ClientCertVerified, rustls::Error> {
        if !self.pins.is_empty() && !certificate_matches_pins(end_entity.as_ref(), &self.pins) {
            return Err(rustls::Error::General(
                "unrecognized client certificate public key".into(),
            ));
        }
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, certificate, signature, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, certificate, signature, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

fn certificate_matches_pins(certificate: &[u8], pins: &[[u8; 32]]) -> bool {
    x509_parser::parse_x509_certificate(certificate)
        .ok()
        .is_some_and(|(_, certificate)| {
            let digest = Sha256::digest(certificate.tbs_certificate.subject_pki.raw);
            pins.iter().any(|pin| digest[..] == pin[..])
        })
}

fn socket(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

pub(crate) fn configure_tcp(socket: &TcpStream) -> std::io::Result<()> {
    socket.set_nodelay(true)?;
    // Explicitly disable TCP Fast Open so the kernel cannot send data
    // during the SYN phase, which some middleboxes drop or mishandle.
    #[cfg(target_os = "linux")]
    {
        let descriptor = std::os::fd::AsRawFd::as_raw_fd(socket);
        let enabled: libc::c_int = 0;
        let _ = unsafe {
            libc::setsockopt(
                descriptor,
                libc::IPPROTO_TCP,
                libc::TCP_FASTOPEN_CONNECT,
                std::ptr::from_ref(&enabled).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
    }
    Ok(())
}

pub fn build_client(
    outbound: &Outbound,
    resolver: Option<Arc<crate::dns::DnsResolver>>,
) -> Result<anytls::Client> {
    validate_outbound(outbound)?;
    let server = outbound
        .server
        .as_ref()
        .context("AnyTLS outbound requires server")?
        .clone();
    let port = outbound.server_port.unwrap_or(443);
    let password = outbound
        .password
        .as_ref()
        .context("AnyTLS outbound requires password")?
        .clone();
    let tls = outbound
        .tls
        .as_ref()
        .filter(|tls| tls.enabled)
        .context("AnyTLS outbound requires TLS")?
        .clone();
    let server_name = tls.server_name.clone().unwrap_or_else(|| server.clone());
    let static_ech = load_static_ech(&tls)?;
    let dns_ech_name = tls
        .ech
        .as_ref()
        .filter(|ech| ech.enabled && static_ech.is_none())
        .map(|ech| {
            ech.query_server_name
                .clone()
                .unwrap_or_else(|| server_name.clone())
        });
    build_client_tls(&tls, static_ech.clone())?;
    let padding = Arc::new(RwLock::new(anytls::PaddingScheme::default()));
    let connector_padding = padding.clone();
    let connector: Connector = Arc::new(move || {
        let server = server.clone();
        let password = password.clone();
        let server_name = server_name.clone();
        let tls_options = tls.clone();
        let static_ech = static_ech.clone();
        let dns_ech_name = dns_ech_name.clone();
        let resolver = resolver.clone();
        let padding = connector_padding.clone();
        Box::pin(async move {
            let socket = tokio::time::timeout(
                Duration::from_secs(5),
                TcpStream::connect((server.as_str(), port)),
            )
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "AnyTLS connect timeout")
            })??;
            configure_tcp(&socket)?;
            let ech_config = if let Some(ech) = static_ech {
                Some(ech)
            } else if let Some(query_name) = dns_ech_name {
                Some(
                    resolver
                        .as_ref()
                        .ok_or_else(|| {
                            std::io::Error::new(
                                std::io::ErrorKind::InvalidInput,
                                "DNS-discovered ECH requires a DNS configuration",
                            )
                        })?
                        .cached_ech_config(&query_name)
                        .await
                        .map_err(std::io::Error::other)?,
                )
            } else {
                None
            };
            let tls_config =
                build_client_tls(&tls_options, ech_config).map_err(std::io::Error::other)?;
            let name = ServerName::try_from(server_name)
                .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
            let mut tls = TlsConnector::from(tls_config)
                .connect(name, socket)
                .await
                .map_err(std::io::Error::other)?;
            let scheme = padding.read().await.clone();
            client_authentication(&mut tls, &password, &scheme).await?;
            Ok(Box::new(tls) as anytls::BoxedIo)
        })
    });
    Ok(anytls::Client::new(
        connector,
        SessionConfig {
            padding,
            implementation: format!("xhttp-rs/{}", env!("CARGO_PKG_VERSION")),
            ..SessionConfig::default()
        },
        ClientOptions {
            idle_session_check_interval: parse_duration(
                outbound.idle_session_check_interval.as_deref(),
                Duration::from_secs(30),
            )?,
            idle_session_timeout: parse_duration(
                outbound.idle_session_timeout.as_deref(),
                Duration::from_secs(30),
            )?,
            min_idle_session: outbound.min_idle_session.unwrap_or(0),
            disable_reuse: outbound.disable_reuse,
        },
    ))
}

pub fn validate_outbound(outbound: &Outbound) -> Result<()> {
    let tls = outbound
        .tls
        .as_ref()
        .filter(|tls| tls.enabled)
        .context("AnyTLS outbound requires TLS")?;
    build_client_tls(tls, load_static_ech(tls)?)?;
    parse_duration(
        outbound.idle_session_check_interval.as_deref(),
        Duration::from_secs(30),
    )?;
    parse_duration(
        outbound.idle_session_timeout.as_deref(),
        Duration::from_secs(30),
    )?;
    Ok(())
}

fn build_client_tls(
    tls: &TlsConfig,
    ech_config: Option<Vec<u8>>,
) -> Result<Arc<rustls::ClientConfig>> {
    let ca_pem = crate::tls::load_optional_material(
        &tls.certificate,
        tls.certificate_path.as_deref(),
        "AnyTLS CA certificate",
    )?;
    let client_certificate = crate::tls::load_optional_material(
        &tls.client_certificate,
        tls.client_certificate_path.as_deref(),
        "AnyTLS client certificate",
    )?;
    let client_key = crate::tls::load_optional_material(
        &tls.client_key,
        tls.client_key_path.as_deref(),
        "AnyTLS client key",
    )?;
    crate::tls::build_client_config(&crate::tls::ClientOptions {
        insecure: tls.insecure,
        include_native_roots: ca_pem.is_none(),
        ca_pem,
        alpn: tls
            .alpn
            .iter()
            .map(|value| value.as_bytes().to_vec())
            .collect(),
        ech_config,
        certificate_public_key_sha256: crate::tls::decode_public_key_pins(
            &tls.certificate_public_key_sha256,
        )?,
        client_certificate,
        client_key,
        disable_sni: tls.disable_sni,
        min_version: tls
            .min_version
            .as_deref()
            .map(crate::tls::parse_tls_version)
            .transpose()?,
        max_version: tls
            .max_version
            .as_deref()
            .map(crate::tls::parse_tls_version)
            .transpose()?,
    })
}

fn load_static_ech(tls: &TlsConfig) -> Result<Option<Vec<u8>>> {
    let Some(ech) = tls.ech.as_ref().filter(|ech| ech.enabled) else {
        return Ok(None);
    };
    crate::tls::load_optional_material(&ech.config, ech.config_path.as_deref(), "ECH config")
}

fn parse_duration(value: Option<&str>, default: Duration) -> Result<Duration> {
    crate::util::parse_duration_or(value, default).context("invalid AnyTLS duration")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn tcp_configuration_disables_nagle() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (server, _) = listener.accept().await.unwrap();
        configure_tcp(&client).unwrap();
        configure_tcp(&server).unwrap();
        assert!(client.nodelay().unwrap());
        assert!(server.nodelay().unwrap());
    }

    #[test]
    fn formats_ipv4_domain_and_ipv6_sockets() {
        assert_eq!(socket("127.0.0.1", 443), "127.0.0.1:443");
        assert_eq!(socket("example.com", 8443), "example.com:8443");
        assert_eq!(socket("::1", 443), "[::1]:443");
        assert_eq!(socket("[::1]", 443), "[::1]:443");
    }

    #[test]
    fn parses_and_rejects_session_durations() {
        let default = Duration::from_secs(30);
        assert_eq!(parse_duration(None, default).unwrap(), default);
        assert_eq!(
            parse_duration(Some("250ms"), default).unwrap(),
            Duration::from_millis(250)
        );
        assert_eq!(
            parse_duration(Some("2m"), default).unwrap(),
            Duration::from_secs(120)
        );
        for invalid in ["", "30", "1.5s", "-1s", "seconds"] {
            assert!(parse_duration(Some(invalid), default).is_err(), "{invalid}");
        }
    }
}

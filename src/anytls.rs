use crate::singbox::{DnsConfig, Inbound, Outbound, RouteConfig, TlsConfig};
use anyhow::{Context, Result, bail};
use anytls::{ClientOptions, Connector, SessionConfig, client_authentication};
use base64::Engine;
use boring::{
    hpke::HpkeKey,
    pkey::PKey,
    ssl::{AlpnError, SslAcceptor, SslEchKeys, SslMethod, SslVerifyMode},
    x509::{X509, store::X509StoreBuilder},
};
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

#[derive(Clone)]
enum ServerTls {
    Rustls(TlsAcceptor),
    Boring(Arc<SslAcceptor>),
}

impl ServerTls {
    async fn accept(&self, socket: TcpStream) -> Result<anytls::BoxedIo> {
        match self {
            Self::Rustls(acceptor) => Ok(Box::new(
                acceptor
                    .accept(socket)
                    .await
                    .context("AnyTLS TLS handshake")?,
            )),
            Self::Boring(acceptor) => Ok(Box::new(
                tokio_boring::accept(acceptor, socket)
                    .await
                    .context("AnyTLS ECH TLS handshake")?,
            )),
        }
    }
}

pub async fn run_inbound(
    inbound: Inbound,
    outbounds: Vec<Outbound>,
    route: Option<RouteConfig>,
    dns: Option<DnsConfig>,
) -> Result<()> {
    let runtime = Arc::new(crate::proxy::build_runtime(outbounds, route, dns).await?);
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
                    Some(tls) => tls.accept(socket).await?,
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

fn build_server_tls(tls: &TlsConfig) -> Result<ServerTls> {
    let certificate = load_required_material(
        &tls.certificate,
        tls.certificate_path.as_deref(),
        "AnyTLS TLS certificate",
    )?;
    let key = load_required_material(&tls.key, tls.key_path.as_deref(), "AnyTLS TLS private key")?;
    if let Some(ech) = tls.ech.as_ref().filter(|ech| ech.enabled) {
        return build_boring_server_tls(tls, ech, &certificate, &key).map(ServerTls::Boring);
    }
    build_rustls_server_tls(tls, &certificate, &key).map(ServerTls::Rustls)
}

pub(crate) fn validate_server_tls(tls: &TlsConfig) -> Result<()> {
    build_server_tls(tls).map(drop)
}

fn build_rustls_server_tls(tls: &TlsConfig, certificate: &[u8], key: &[u8]) -> Result<TlsAcceptor> {
    crate::install_crypto_provider();
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

fn build_boring_server_tls(
    tls: &TlsConfig,
    ech: &crate::singbox::EchConfig,
    certificate: &[u8],
    key: &[u8],
) -> Result<Arc<SslAcceptor>> {
    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls())
        .context("create AnyTLS ECH TLS acceptor")?;
    let mut certificates = X509::stack_from_pem(certificate).context("parse TLS certificate")?;
    if certificates.is_empty() {
        bail!("AnyTLS TLS certificate input contains no certificates")
    }
    builder
        .set_certificate(&certificates.remove(0))
        .context("set TLS certificate")?;
    for certificate in certificates {
        builder
            .add_extra_chain_cert(certificate)
            .context("set TLS certificate chain")?;
    }
    let private_key = PKey::private_key_from_pem(key).context("parse TLS private key")?;
    builder
        .set_private_key(&private_key)
        .context("set TLS private key")?;
    builder
        .check_private_key()
        .context("check TLS private key")?;

    configure_boring_client_auth(&mut builder, tls)?;
    if !tls.alpn.is_empty() {
        let protocols = encode_alpn(&tls.alpn)?;
        builder.set_alpn_select_callback(move |_, client| {
            select_client_alpn(&protocols, client).ok_or(AlpnError::NOACK)
        });
    }

    let raw_keys = load_required_material(&ech.key, ech.key_path.as_deref(), "AnyTLS ECH key")?;
    let entries = parse_ech_keys(&raw_keys)?;
    let mut ech_keys = SslEchKeys::builder().context("create ECH key set")?;
    for (private_key, config) in entries {
        ech_keys
            .add_key(
                true,
                &config,
                HpkeKey::dhkem_p256_sha256(&private_key).context("parse ECH private key")?,
            )
            .context("add ECH key")?;
    }
    builder
        .set_ech_keys(&ech_keys.build())
        .context("configure ECH keys")?;
    Ok(Arc::new(builder.build()))
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

fn configure_boring_client_auth(
    builder: &mut boring::ssl::SslAcceptorBuilder,
    tls: &TlsConfig,
) -> Result<()> {
    let authentication = effective_client_authentication(tls);
    if authentication == "no" {
        return Ok(());
    }
    let required = matches!(authentication, "require-any" | "require-and-verify");
    let mode = SslVerifyMode::PEER
        | if required {
            SslVerifyMode::FAIL_IF_NO_PEER_CERT
        } else {
            SslVerifyMode::empty()
        };
    let pins = crate::tls::decode_public_key_pins(&tls.client_certificate_public_key_sha256)?;
    if matches!(authentication, "request" | "require-any") || !pins.is_empty() {
        builder.set_verify_callback(mode, move |_, context| {
            if context.error_depth() != 0 || pins.is_empty() {
                return true;
            }
            context
                .current_cert()
                .and_then(|certificate| certificate.public_key().ok())
                .and_then(|key| key.public_key_to_der().ok())
                .is_some_and(|key| {
                    let digest = Sha256::digest(key);
                    pins.iter().any(|pin| digest[..] == pin[..])
                })
        });
        return Ok(());
    }
    if !matches!(authentication, "verify-if-given" | "require-and-verify") {
        bail!("unknown client_authentication: {authentication}")
    }
    let pem = load_required_material(
        &tls.client_certificate,
        tls.client_certificate_path.as_deref(),
        "AnyTLS client CA certificate",
    )?;
    let mut store = X509StoreBuilder::new().context("create client CA store")?;
    let certificates = X509::stack_from_pem(&pem).context("parse client CA certificate")?;
    if certificates.is_empty() {
        bail!("AnyTLS client CA certificate input contains no certificates")
    }
    for certificate in certificates {
        store.add_cert(certificate).context("add client CA")?;
    }
    builder
        .set_verify_cert_store(store.build())
        .context("set client CA store")?;
    builder.set_verify(mode);
    Ok(())
}

fn certificate_matches_pins(certificate: &[u8], pins: &[[u8; 32]]) -> bool {
    x509_parser::parse_x509_certificate(certificate)
        .ok()
        .is_some_and(|(_, certificate)| {
            let digest = Sha256::digest(certificate.tbs_certificate.subject_pki.raw);
            pins.iter().any(|pin| digest[..] == pin[..])
        })
}

fn encode_alpn(protocols: &[String]) -> Result<Vec<u8>> {
    let mut encoded = Vec::new();
    for protocol in protocols {
        encoded.push(
            protocol
                .len()
                .try_into()
                .context("ALPN protocol is longer than 255 bytes")?,
        );
        encoded.extend_from_slice(protocol.as_bytes());
    }
    Ok(encoded)
}

fn select_client_alpn<'a>(server: &[u8], mut client: &'a [u8]) -> Option<&'a [u8]> {
    while let Some((&length, rest)) = client.split_first() {
        let length = length as usize;
        if rest.len() < length {
            return None;
        }
        let (protocol, remaining) = rest.split_at(length);
        if alpn_wire_contains(server, protocol) {
            return Some(protocol);
        }
        client = remaining;
    }
    None
}

fn alpn_wire_contains(mut wire: &[u8], expected: &[u8]) -> bool {
    while let Some((&length, rest)) = wire.split_first() {
        let length = length as usize;
        if rest.len() < length {
            return false;
        }
        let (protocol, remaining) = rest.split_at(length);
        if protocol == expected {
            return true;
        }
        wire = remaining;
    }
    false
}

fn parse_ech_keys(raw: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let text = std::str::from_utf8(raw).context("ECH keys are not UTF-8 PEM")?;
    let body = text
        .split_once("-----BEGIN ECH KEYS-----")
        .and_then(|(_, rest)| rest.split_once("-----END ECH KEYS-----"))
        .map(|(body, _)| body)
        .context("invalid ECH keys PEM")?;
    let der = base64::engine::general_purpose::STANDARD
        .decode(body.split_whitespace().collect::<String>())
        .context("decode ECH keys PEM")?;
    let mut cursor = der.as_slice();
    let mut entries = Vec::new();
    while !cursor.is_empty() {
        let private_length = take_u16(&mut cursor)?;
        let private_key = take_bytes(&mut cursor, private_length)?.to_vec();
        let config_length = take_u16(&mut cursor)?;
        let config = take_bytes(&mut cursor, config_length)?.to_vec();
        entries.push((private_key, config));
    }
    if entries.is_empty() {
        bail!("ECH keys PEM contains no keys")
    }
    Ok(entries)
}

fn take_u16(input: &mut &[u8]) -> Result<usize> {
    let bytes = take_bytes(input, 2)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]) as usize)
}

fn take_bytes<'a>(input: &mut &'a [u8], length: usize) -> Result<&'a [u8]> {
    if input.len() < length {
        bail!("truncated ECH keys")
    }
    let (value, rest) = input.split_at(length);
    *input = rest;
    Ok(value)
}

fn socket(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

pub(crate) fn configure_tcp(socket: &TcpStream) -> std::io::Result<()> {
    socket.set_nodelay(true)
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
                        .ech_config(&query_name)
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

    #[test]
    fn parses_sing_box_ech_keys_pem() {
        let mut raw = Vec::new();
        raw.extend(3u16.to_be_bytes());
        raw.extend([1, 2, 3]);
        raw.extend(4u16.to_be_bytes());
        raw.extend([4, 5, 6, 7]);
        let pem = format!(
            "-----BEGIN ECH KEYS-----\n{}\n-----END ECH KEYS-----\n",
            base64::engine::general_purpose::STANDARD.encode(raw)
        );
        assert_eq!(
            parse_ech_keys(pem.as_bytes()).unwrap(),
            vec![(vec![1, 2, 3], vec![4, 5, 6, 7])]
        );
    }

    #[test]
    fn rejects_truncated_ech_keys() {
        let pem = "-----BEGIN ECH KEYS-----\nAAMBAg==\n-----END ECH KEYS-----\n";
        assert!(parse_ech_keys(pem.as_bytes()).is_err());
    }

    #[test]
    fn rejects_empty_and_non_pem_ech_keys() {
        assert!(parse_ech_keys(b"").is_err());
        assert!(parse_ech_keys(b"not pem").is_err());
        let empty = "-----BEGIN ECH KEYS-----\n\n-----END ECH KEYS-----\n";
        assert!(parse_ech_keys(empty.as_bytes()).is_err());
    }

    #[test]
    fn selects_alpn_in_client_order() {
        let server = encode_alpn(&["h2".into(), "http/1.1".into()]).unwrap();
        assert_eq!(
            select_client_alpn(&server, b"\x08http/1.1\x02h2"),
            Some(&b"http/1.1"[..])
        );
        assert_eq!(select_client_alpn(&server, b"\x02h3"), None);
    }
}

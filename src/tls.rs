use anyhow::{Context, Result, bail};
use base64::Engine;
use rustls::{
    DigitallySignedStruct, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{
        CertificateDer, EchConfigListBytes, PrivateKeyDer, ServerName, UnixTime, pem::PemObject,
    },
};
use sha2::{Digest, Sha256};
use std::{fmt, sync::Arc};

#[derive(Clone, Debug, Default)]
pub struct ClientOptions {
    pub insecure: bool,
    pub include_native_roots: bool,
    pub ca_pem: Option<Vec<u8>>,
    pub alpn: Vec<Vec<u8>>,
    pub ech_config: Option<Vec<u8>>,
    pub certificate_public_key_sha256: Vec<[u8; 32]>,
    pub client_certificate: Option<Vec<u8>>,
    pub client_key: Option<Vec<u8>>,
    pub disable_sni: bool,
    pub min_version: Option<u16>,
    pub max_version: Option<u16>,
}

/// Parse a sing-box TLS version string (`1.2` or `1.3`) into the wire
/// protocol version number used by rustls.
pub fn parse_tls_version(value: &str) -> Result<u16> {
    match value {
        "1.2" => Ok(0x0303),
        "1.3" => Ok(0x0304),
        value => bail!("unsupported TLS version: {value}"),
    }
}

fn protocol_version_number(version: rustls::ProtocolVersion) -> u16 {
    match version {
        rustls::ProtocolVersion::SSLv2 => 0x0002,
        rustls::ProtocolVersion::SSLv3 => 0x0300,
        rustls::ProtocolVersion::TLSv1_0 => 0x0301,
        rustls::ProtocolVersion::TLSv1_1 => 0x0302,
        rustls::ProtocolVersion::TLSv1_2 => 0x0303,
        rustls::ProtocolVersion::TLSv1_3 => 0x0304,
        rustls::ProtocolVersion::DTLSv1_0 => 0xFEFF,
        rustls::ProtocolVersion::DTLSv1_2 => 0xFEFD,
        rustls::ProtocolVersion::DTLSv1_3 => 0xFEFC,
        rustls::ProtocolVersion::Unknown(value) => value,
        _ => 0,
    }
}

fn select_protocol_versions(
    min: Option<u16>,
    max: Option<u16>,
) -> Vec<&'static rustls::SupportedProtocolVersion> {
    let mut versions = Vec::new();
    for version in [&rustls::version::TLS13, &rustls::version::TLS12] {
        let number = protocol_version_number(version.version);
        if min.is_none_or(|bound| number >= bound) && max.is_none_or(|bound| number <= bound) {
            versions.push(version);
        }
    }
    versions
}

pub fn build_client_config(options: &ClientOptions) -> Result<Arc<rustls::ClientConfig>> {
    crate::install_crypto_provider();
    if !options.certificate_public_key_sha256.is_empty() && options.ca_pem.is_some() {
        bail!("certificate_public_key_sha256 conflicts with certificate or certificate_path")
    }
    if options.client_certificate.is_some() != options.client_key.is_some() {
        bail!("client certificate and client key must be provided together")
    }

    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut roots = rustls::RootCertStore::empty();
    if options.include_native_roots {
        let native = rustls_native_certs::load_native_certs();
        for certificate in native.certs {
            roots
                .add(certificate)
                .context("add native TLS root certificate")?;
        }
        if !options.insecure
            && options.certificate_public_key_sha256.is_empty()
            && !native.errors.is_empty()
            && roots.is_empty()
        {
            bail!("no native TLS roots are available")
        }
    }
    if let Some(pem) = &options.ca_pem {
        add_ca_pem(&mut roots, pem)?;
    }

    let builder = rustls::ClientConfig::builder_with_provider(provider.clone());
    let builder = if let Some(raw) = &options.ech_config {
        builder.with_ech(rustls::client::EchMode::Enable(parse_ech_config(raw)?))?
    } else {
        let versions = select_protocol_versions(options.min_version, options.max_version);
        if versions.is_empty() {
            bail!("TLS min_version/max_version leave no supported protocol versions")
        }
        builder.with_protocol_versions(&versions)?
    };
    let builder = if options.insecure || !options.certificate_public_key_sha256.is_empty() {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(DirectCertificateVerifier {
                pins: options.certificate_public_key_sha256.clone(),
                algorithms: provider.signature_verification_algorithms,
            }))
    } else {
        builder.with_root_certificates(roots)
    };
    let mut config = match (&options.client_certificate, &options.client_key) {
        (Some(certificate), Some(key)) => builder
            .with_client_auth_cert(parse_certificates(certificate)?, parse_private_key(key)?)
            .context("build TLS client certificate")?,
        (None, None) => builder.with_no_client_auth(),
        _ => unreachable!("client certificate/key pairing was validated"),
    };
    config.alpn_protocols = options.alpn.clone();
    config.enable_sni = !options.disable_sni;
    Ok(Arc::new(config))
}

pub fn parse_ech_config(raw: &[u8]) -> Result<rustls::client::EchConfig> {
    let bytes = if raw.starts_with(b"-----BEGIN") {
        let normalized = String::from_utf8_lossy(raw)
            .replace("BEGIN ECH CONFIGS", "BEGIN ECHCONFIG")
            .replace("END ECH CONFIGS", "END ECHCONFIG")
            .into_bytes();
        EchConfigListBytes::from_pem_slice(&normalized).context("parse ECH config PEM")?
    } else {
        EchConfigListBytes::from(raw.to_vec())
    };
    rustls::client::EchConfig::new(bytes, rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES)
        .context("select supported ECH config")
}

pub fn load_optional_material(
    inline: &[String],
    path: Option<&str>,
    description: &str,
) -> Result<Option<Vec<u8>>> {
    if !inline.is_empty() && path.is_some() {
        bail!("inline {description} and {description}_path are mutually exclusive")
    }
    if !inline.is_empty() {
        Ok(Some(inline.join("\n").into_bytes()))
    } else if let Some(path) = path {
        Ok(Some(
            std::fs::read(path).with_context(|| format!("read {description}"))?,
        ))
    } else {
        Ok(None)
    }
}

pub fn decode_public_key_pins(values: &[String]) -> Result<Vec<[u8; 32]>> {
    values
        .iter()
        .map(|value| {
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(value)
                .context("decode certificate_public_key_sha256")?;
            decoded.try_into().map_err(|value: Vec<u8>| {
                anyhow::anyhow!(
                    "certificate_public_key_sha256 must decode to 32 bytes, got {}",
                    value.len()
                )
            })
        })
        .collect()
}

fn add_ca_pem(roots: &mut rustls::RootCertStore, pem: &[u8]) -> Result<()> {
    let mut added = 0usize;
    for certificate in rustls_pemfile::certs(&mut std::io::Cursor::new(pem)) {
        roots
            .add(certificate?)
            .context("add custom CA certificate")?;
        added += 1;
    }
    if added == 0 {
        bail!("custom CA input contains no certificates")
    }
    Ok(())
}

fn parse_certificates(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>> {
    let certificates =
        rustls_pemfile::certs(&mut std::io::Cursor::new(pem)).collect::<Result<Vec<_>, _>>()?;
    if certificates.is_empty() {
        bail!("client certificate input contains no certificates")
    }
    Ok(certificates)
}

fn parse_private_key(pem: &[u8]) -> Result<PrivateKeyDer<'static>> {
    rustls_pemfile::private_key(&mut std::io::Cursor::new(pem))?
        .context("client private key input contains no private key")
}

#[derive(Debug)]
struct DirectCertificateVerifier {
    pins: Vec<[u8; 32]>,
    algorithms: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for DirectCertificateVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        if self.pins.is_empty() {
            return Ok(ServerCertVerified::assertion());
        }
        let (_, certificate) =
            x509_parser::parse_x509_certificate(end_entity.as_ref()).map_err(|error| {
                rustls::Error::General(format!("parse pinned certificate: {error}"))
            })?;
        let digest = Sha256::digest(certificate.tbs_certificate.subject_pki.raw);
        if self.pins.iter().any(|pin| digest[..] == pin[..]) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!(
                "unrecognized remote public key: {}",
                base64::engine::general_purpose::STANDARD.encode(&digest[..])
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, certificate, signature, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, certificate, signature, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

impl fmt::Display for DirectCertificateVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.pins.is_empty() {
            formatter.write_str("certificate verification disabled")
        } else {
            formatter.write_str("certificate public-key pin verification")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sing_box_ech_pem_is_accepted() {
        parse_ech_config(
            b"-----BEGIN ECH CONFIGS-----\nAET+DQBAAAAgACCT/A3lRXEPEOOFzhZ+AQwpE+z8kKlc2pt8L9tngMF3EwAMAAEAAQABAAIAAQADAAlsb2NhbGhvc3QAAA==\n-----END ECH CONFIGS-----",
        )
        .unwrap();
    }

    #[test]
    fn client_certificate_requires_a_key() {
        let options = ClientOptions {
            insecure: true,
            client_certificate: Some(Vec::new()),
            ..Default::default()
        };
        assert!(build_client_config(&options).is_err());
    }

    #[test]
    fn protocol_version_selection_honors_min_and_max() {
        let all = select_protocol_versions(None, None);
        assert_eq!(all.len(), 2);
        assert_eq!(select_protocol_versions(Some(0x0304), None).len(), 1);
        assert_eq!(select_protocol_versions(None, Some(0x0303)).len(), 1);
        assert_eq!(
            select_protocol_versions(Some(0x0304), Some(0x0303)).len(),
            0
        );
        assert_eq!(select_protocol_versions(Some(0x0303), Some(0x0304)).len(), 2);
    }

    #[test]
    fn parse_tls_version_accepts_12_and_13() {
        assert_eq!(parse_tls_version("1.2").unwrap(), 0x0303);
        assert_eq!(parse_tls_version("1.3").unwrap(), 0x0304);
        assert!(parse_tls_version("1.1").is_err());
        assert!(parse_tls_version("1.4").is_err());
    }

    #[test]
    fn disable_sni_is_applied() {
        let config = build_client_config(&ClientOptions {
            insecure: true,
            disable_sni: true,
            ..Default::default()
        })
        .unwrap();
        assert!(!config.enable_sni);
        let config = build_client_config(&ClientOptions {
            insecure: true,
            ..Default::default()
        })
        .unwrap();
        assert!(config.enable_sni);
    }
}

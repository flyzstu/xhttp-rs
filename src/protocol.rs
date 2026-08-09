use anyhow::{Context, Result, bail};
use axum::{
    body::Bytes,
    http::{HeaderMap, HeaderName, HeaderValue, Uri},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::Rng;
use url::Url;

use crate::config::{Placement, TransportConfig};

pub const PADDING_QUERY_KEY: &str = "x_padding";

pub fn add_common_headers(config: &TransportConfig, headers: &mut HeaderMap) -> Result<()> {
    for (name, value) in &config.headers {
        headers.insert(
            HeaderName::try_from(name).context("invalid configured header name")?,
            HeaderValue::try_from(value).context("invalid configured header value")?,
        );
    }
    if let Some(token) = &config.token {
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::try_from(format!("Bearer {token}"))?,
        );
    }
    Ok(())
}

pub fn apply_padding(config: &TransportConfig, url: &mut Url, headers: &mut HeaderMap) {
    let length = if config.padding_min == config.padding_max {
        config.padding_min
    } else {
        rand::rng().random_range(config.padding_min..=config.padding_max)
    };
    let value = padding_value(&config.padding_method, length);
    let (placement, key, header) = if config.padding_obfs {
        (
            config.padding_placement,
            config.padding_key.as_str(),
            config.padding_header.as_str(),
        )
    } else {
        (Placement::QueryInHeader, PADDING_QUERY_KEY, "Referer")
    };
    match placement {
        Placement::Header => {
            if let Ok(v) = HeaderValue::try_from(&value)
                && let Ok(name) = HeaderName::try_from(header)
            {
                headers.insert(name, v);
            }
        }
        Placement::Cookie => {
            let _ = append_cookie(headers, key, &value);
        }
        Placement::Query => {
            url.query_pairs_mut().append_pair(key, &value);
        }
        Placement::QueryInHeader => {
            let mut reference = url.clone();
            reference.query_pairs_mut().append_pair(key, &value);
            if let (Ok(name), Ok(v)) = (
                HeaderName::try_from(header),
                HeaderValue::try_from(reference.as_str()),
            ) {
                headers.insert(name, v);
            }
        }
        _ => {}
    }
}

pub fn valid_padding(config: &TransportConfig, uri: &Uri, headers: &HeaderMap) -> bool {
    let (placement, key, header) = if config.padding_obfs {
        (
            config.padding_placement,
            config.padding_key.as_str(),
            config.padding_header.as_str(),
        )
    } else {
        (Placement::QueryInHeader, PADDING_QUERY_KEY, "Referer")
    };
    let value = match placement {
        Placement::Header => headers
            .get(header)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned),
        Placement::Cookie => cookie_value(headers, key),
        Placement::Query => uri.query().and_then(|q| {
            url::form_urlencoded::parse(q.as_bytes())
                .find_map(|(k, v)| (k == key).then(|| v.into_owned()))
        }),
        Placement::QueryInHeader => headers
            .get(header)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| Url::parse(v).ok())
            .and_then(|u| {
                u.query_pairs()
                    .find_map(|(k, v)| (k == key).then(|| v.into_owned()))
            }),
        _ => None,
    };
    let Some(value) = value else { return false };
    let length = if config.padding_method == "tokenish" {
        huffman_length(value.as_bytes())
    } else {
        value.len()
    };
    length + 2 >= config.padding_min && length <= config.padding_max + 2
}

pub fn apply_response_padding(config: &TransportConfig, headers: &mut HeaderMap) {
    let length = if config.padding_min == config.padding_max {
        config.padding_min
    } else {
        rand::rng().random_range(config.padding_min..=config.padding_max)
    };
    let value = padding_value(&config.padding_method, length);
    if !config.padding_obfs {
        if let Ok(v) = HeaderValue::try_from(value) {
            headers.insert("x-padding", v);
        }
        return;
    }
    match config.padding_placement {
        Placement::Header => {
            if let (Ok(k), Ok(v)) = (
                HeaderName::try_from(&config.padding_header),
                HeaderValue::try_from(value),
            ) {
                headers.insert(k, v);
            }
        }
        Placement::Cookie => {
            if let Ok(v) =
                HeaderValue::try_from(format!("{}={}; Path=/", config.padding_key, value))
            {
                headers.append(axum::http::header::SET_COOKIE, v);
            }
        }
        _ => {}
    }
}
fn padding_value(method: &str, length: usize) -> String {
    if method != "tokenish" {
        return "X".repeat(length);
    }
    const ALPHABET: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let mut value = Vec::with_capacity(length + length / 2 + 8);
    for index in 0..value.capacity() {
        value.push(ALPHABET[(index * 37 + length * 17) % ALPHABET.len()]);
        if huffman_length(&value) >= length {
            break;
        }
    }
    String::from_utf8(value).unwrap_or_default()
}
fn huffman_length(value: &[u8]) -> usize {
    let mut encoded = Vec::new();
    if httlib_huffman::encode(value, &mut encoded).is_ok() {
        encoded.len()
    } else {
        value.len()
    }
}

pub fn authorized(config: &TransportConfig, headers: &HeaderMap) -> bool {
    let Some(token) = &config.token else {
        return true;
    };
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|value| value == format!("Bearer {token}"))
}

pub fn apply_metadata(
    config: &TransportConfig,
    url: &mut Url,
    headers: &mut HeaderMap,
    session: Option<&str>,
    sequence: Option<u64>,
) -> Result<()> {
    if let Some(value) = session {
        apply_value(
            config.session_placement,
            &config.session_key,
            value,
            url,
            headers,
        )?;
    }
    if let Some(value) = sequence {
        apply_value(
            config.sequence_placement,
            &config.sequence_key,
            &value.to_string(),
            url,
            headers,
        )?;
    }
    Ok(())
}

fn apply_value(
    placement: Placement,
    key: &str,
    value: &str,
    url: &mut Url,
    headers: &mut HeaderMap,
) -> Result<()> {
    match placement {
        Placement::Path => {
            let mut path = url.path().trim_end_matches('/').to_owned();
            path.push('/');
            path.push_str(value);
            url.set_path(&path);
        }
        Placement::Query => {
            url.query_pairs_mut().append_pair(key, value);
        }
        Placement::Header => {
            headers.insert(HeaderName::try_from(key)?, HeaderValue::try_from(value)?);
        }
        Placement::Cookie => append_cookie(headers, key, value)?,
        _ => bail!("invalid metadata placement"),
    }
    Ok(())
}

fn append_cookie(headers: &mut HeaderMap, key: &str, value: &str) -> Result<()> {
    let cookie = format!("{key}={value}");
    headers.append(axum::http::header::COOKIE, HeaderValue::try_from(cookie)?);
    Ok(())
}

pub fn extract_metadata(
    config: &TransportConfig,
    uri: &Uri,
    headers: &HeaderMap,
) -> (Option<String>, Option<u64>) {
    let suffix = uri.path().strip_prefix(&config.path).unwrap_or("");
    let mut path_values = suffix
        .trim_matches('/')
        .split('/')
        .filter(|v| !v.is_empty());
    let mut read = |placement: Placement, key: &str| -> Option<String> {
        match placement {
            Placement::Path => path_values.next().map(str::to_owned),
            Placement::Query => query_value(uri, key),
            Placement::Header => headers
                .get(key)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned),
            Placement::Cookie => cookie_value(headers, key),
            _ => None,
        }
    };
    let session = read(config.session_placement, &config.session_key);
    let sequence =
        read(config.sequence_placement, &config.sequence_key).and_then(|v| v.parse().ok());
    (session, sequence)
}

fn query_value(uri: &Uri, key: &str) -> Option<String> {
    let mut found = None;
    for (name, value) in url::form_urlencoded::parse(uri.query()?.as_bytes()) {
        if name == key {
            found = Some(value.into_owned());
        }
    }
    found
}

fn cookie_value(headers: &HeaderMap, key: &str) -> Option<String> {
    headers
        .get_all(axum::http::header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .find_map(|part| {
            let (name, value) = part.trim().split_once('=')?;
            (name == key).then(|| value.to_owned())
        })
}

#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub fn fuzz_cookie(input: &[u8]) {
    if let Ok(value) = HeaderValue::from_bytes(input) {
        let mut headers = HeaderMap::new();
        headers.append(axum::http::header::COOKIE, value);
        let _ = cookie_value(&headers, "x_session");
    }
}

#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub fn fuzz_metadata(input: &[u8]) {
    let config = TransportConfig::default();
    let encoded = URL_SAFE_NO_PAD.encode(input);
    if let Ok(uri) = format!("/xhttp/{encoded}/18446744073709551615").parse::<Uri>() {
        let _ = extract_metadata(&config, &uri, &HeaderMap::new());
    }
}

pub fn put_payload(
    config: &TransportConfig,
    payload: &[u8],
    headers: &mut HeaderMap,
) -> Result<Option<Vec<u8>>> {
    match config.data_placement {
        Placement::Body | Placement::Auto => Ok(Some(payload.to_vec())),
        Placement::Header => {
            let encoded = URL_SAFE_NO_PAD.encode(payload);
            for (index, chunk) in encoded.as_bytes().chunks(3_000).enumerate() {
                headers.insert(
                    HeaderName::try_from(format!("{}-{index}", config.data_key))?,
                    HeaderValue::from_bytes(chunk)?,
                );
            }
            Ok(None)
        }
        Placement::Cookie => {
            let encoded = URL_SAFE_NO_PAD.encode(payload);
            for (index, chunk) in encoded.as_bytes().chunks(2_000).enumerate() {
                append_cookie(
                    headers,
                    &format!("{}_{index}", config.data_key),
                    std::str::from_utf8(chunk)?,
                )?;
            }
            Ok(None)
        }
        _ => bail!("invalid payload placement"),
    }
}

pub fn extract_payload(
    config: &TransportConfig,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<Vec<u8>> {
    if config.data_placement == Placement::Auto {
        let mut output = Vec::new();
        for encoded in [
            collect_numbered(
                config,
                |key| {
                    headers
                        .get(key)
                        .and_then(|v| v.to_str().ok())
                        .map(str::to_owned)
                },
                "-",
            ),
            collect_numbered(config, |key| cookie_value(headers, key), "_"),
        ] {
            if !encoded.is_empty() {
                output.extend(
                    URL_SAFE_NO_PAD
                        .decode(encoded)
                        .context("invalid base64url packet payload")?,
                )
            }
        }
        output.extend_from_slice(body);
        return Ok(output);
    }
    let encoded = match config.data_placement {
        Placement::Body => return Ok(body.to_vec()),
        Placement::Header => collect_numbered(
            config,
            |key| {
                headers
                    .get(key)
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_owned)
            },
            "-",
        ),
        Placement::Cookie => collect_numbered(config, |key| cookie_value(headers, key), "_"),
        _ => bail!("invalid payload placement"),
    };
    URL_SAFE_NO_PAD
        .decode(encoded)
        .context("invalid base64url packet payload")
}

pub fn extract_payload_bytes(
    config: &TransportConfig,
    headers: &HeaderMap,
    body: Bytes,
) -> Result<Bytes> {
    Ok(match config.data_placement {
        Placement::Body => body,
        _ => Bytes::from(extract_payload(config, headers, &body)?),
    })
}

fn collect_numbered(
    config: &TransportConfig,
    get: impl Fn(&str) -> Option<String>,
    separator: &str,
) -> String {
    let mut output = String::new();
    for index in 0.. {
        let key = format!("{}{separator}{index}", config.data_key);
        let Some(value) = get(&key) else { break };
        output.push_str(&value);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_metadata_round_trip() {
        let config = TransportConfig::default();
        let mut url = Url::parse("https://example.com/xhttp").unwrap();
        let mut headers = HeaderMap::new();
        apply_metadata(&config, &mut url, &mut headers, Some("session-a"), Some(7)).unwrap();
        let uri: Uri = url[url::Position::BeforePath..].parse().unwrap();
        assert_eq!(
            extract_metadata(&config, &uri, &headers),
            (Some("session-a".into()), Some(7))
        );
    }

    #[test]
    fn query_metadata_reads_lazily_and_preserves_duplicate_semantics() {
        let config = TransportConfig {
            session_placement: Placement::Query,
            sequence_placement: Placement::Query,
            ..Default::default()
        };
        let uri: Uri = "/xhttp?x_session=a&x_session=b&x_seq=42"
            .parse()
            .unwrap();
        assert_eq!(
            extract_metadata(&config, &uri, &HeaderMap::new()),
            (Some("b".into()), Some(42))
        );
        let encoded: Uri = "/xhttp?x_session=a%20b&x_seq=7".parse().unwrap();
        assert_eq!(
            extract_metadata(&config, &encoded, &HeaderMap::new()),
            (Some("a b".into()), Some(7))
        );
        let empty: Uri = "/xhttp".parse().unwrap();
        assert_eq!(
            extract_metadata(&config, &empty, &HeaderMap::new()),
            (None, None)
        );
        let partial: Uri = "/xhttp?x_session=only-session".parse().unwrap();
        assert_eq!(
            extract_metadata(&config, &partial, &HeaderMap::new()),
            (Some("only-session".into()), None)
        );
    }

    #[test]
    fn header_payload_round_trip() {
        let config = TransportConfig {
            data_placement: Placement::Header,
            ..Default::default()
        };
        let payload = vec![42; 9_001];
        let mut headers = HeaderMap::new();
        assert!(
            put_payload(&config, &payload, &mut headers)
                .unwrap()
                .is_none()
        );
        assert_eq!(extract_payload(&config, &headers, &[]).unwrap(), payload);
    }

    #[test]
    fn all_metadata_and_payload_placements_round_trip() {
        let metadata = [
            Placement::Path,
            Placement::Query,
            Placement::Header,
            Placement::Cookie,
        ];
        for session_placement in metadata {
            for sequence_placement in metadata {
                let config = TransportConfig {
                    session_placement,
                    sequence_placement,
                    ..Default::default()
                };
                let mut url = Url::parse("https://example.com/xhttp").unwrap();
                let mut headers = HeaderMap::new();
                apply_metadata(&config, &mut url, &mut headers, Some("session"), Some(42)).unwrap();
                let uri: Uri = url[url::Position::BeforePath..].parse().unwrap();
                assert_eq!(
                    extract_metadata(&config, &uri, &headers),
                    (Some("session".into()), Some(42))
                );
            }
        }

        for placement in [
            Placement::Body,
            Placement::Header,
            Placement::Cookie,
            Placement::Auto,
        ] {
            let config = TransportConfig {
                data_placement: placement,
                ..Default::default()
            };
            let mut headers = HeaderMap::new();
            let body = put_payload(&config, b"payload", &mut headers)
                .unwrap()
                .unwrap_or_default();
            assert_eq!(
                extract_payload(&config, &headers, &body).unwrap(),
                b"payload"
            );
        }
    }

    #[test]
    fn all_padding_placements_and_methods_validate() {
        for placement in [
            Placement::Query,
            Placement::Header,
            Placement::Cookie,
            Placement::QueryInHeader,
        ] {
            for method in ["repeat-x", "tokenish"] {
                let config = TransportConfig {
                    padding_min: 64,
                    padding_max: 64,
                    padding_obfs: true,
                    padding_placement: placement,
                    padding_method: method.into(),
                    ..Default::default()
                };
                let mut url = Url::parse("https://example.com/xhttp").unwrap();
                let mut headers = HeaderMap::new();
                apply_padding(&config, &mut url, &mut headers);
                let uri: Uri = url[url::Position::BeforePath..].parse().unwrap();
                assert!(valid_padding(&config, &uri, &headers));
            }
        }
    }
}

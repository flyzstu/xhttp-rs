use crate::singbox::{RouteRule, RuleSetConfig};
use anyhow::{Context, Result, bail};
use flate2::read::ZlibDecoder;
use std::{
    io::{Cursor, Read},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
};

/// Decoded source-format rule set (JSON with a `rules` array).
#[derive(serde::Deserialize)]
struct SourceRuleSet {
    rules: Vec<RouteRule>,
}

/// Decode rule-set bytes in either source (JSON) or binary (SRS) format.
pub(crate) fn decode_rule_set(data: &[u8], format: &str) -> Result<Vec<RouteRule>> {
    match format {
        "source" => Ok(serde_json::from_slice::<SourceRuleSet>(data)?.rules),
        "binary" => decode(data),
        _ => unreachable!("rule-set format was validated"),
    }
}

/// Determine the rule-set format from an explicit setting or the location's file extension.
pub(crate) fn rule_set_format_for<'a>(set: &'a RuleSetConfig, location: &str) -> Result<&'a str> {
    let format = set.format.as_deref().unwrap_or_else(|| {
        if location
            .split(['?', '#'])
            .next()
            .is_some_and(|path| path.ends_with(".srs"))
        {
            "binary"
        } else {
            "source"
        }
    });
    match format {
        "source" | "binary" => Ok(format),
        value => bail!("unsupported route rule-set format: {value}"),
    }
}

/// On-disk cache path for a remote rule set, keyed by URL hash.
pub(crate) fn rule_set_cache_path(url: &str, format: &str) -> PathBuf {
    use std::{
        collections::hash_map::DefaultHasher,
        hash::{Hash, Hasher},
    };
    let mut hasher = DefaultHasher::new();
    url.hash(&mut hasher);
    let cache_root = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("xhttp-cache"));
    cache_root.join("rule-set").join(format!(
        "{:016x}.{}",
        hasher.finish(),
        if format == "binary" { "srs" } else { "json" }
    ))
}

/// Write fetched rule-set bytes to the on-disk cache.
pub(crate) fn write_rule_set_cache(cache_path: &Path, data: &[u8]) -> Result<()> {
    if let Some(parent) = cache_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create rule-set cache {}", parent.display()))?;
    }
    std::fs::write(cache_path, data)
        .with_context(|| format!("write rule-set cache {}", cache_path.display()))
}

/// Load a remote rule set, preferring the on-disk cache over a network fetch.
pub(crate) fn load_remote_rule_set(set: &RuleSetConfig) -> Result<Vec<RouteRule>> {
    if set
        .download_detour
        .as_deref()
        .is_some_and(|tag| !tag.is_empty())
    {
        bail!("remote rule-set download_detour is not supported")
    }
    let url = set
        .url
        .as_deref()
        .with_context(|| format!("remote rule-set {} requires url", set.tag))?;
    let format = rule_set_format_for(set, url)?;
    let cache_path = rule_set_cache_path(url, format);
    // Prefer the on-disk cache: the background updater refreshes it, so at
    // startup we can route immediately without a network round trip.
    if let Ok(data) = std::fs::read(&cache_path)
        && let Ok(rules) = decode_rule_set(&data, format)
    {
        return Ok(rules);
    }
    let fetched = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?
        .get(url)
        .send()
        .and_then(reqwest::blocking::Response::error_for_status)
        .and_then(|response| response.bytes());
    let data = match fetched {
        Ok(data) => {
            if data.len() > 64 * 1024 * 1024 {
                bail!("remote rule-set {} exceeds 64 MiB", set.tag)
            }
            write_rule_set_cache(&cache_path, &data)?;
            data.to_vec()
        }
        Err(error) => std::fs::read(&cache_path).with_context(|| {
            format!(
                "download remote rule-set {} ({error}) and read cache {}",
                set.tag,
                cache_path.display()
            )
        })?,
    };
    decode_rule_set(&data, format).with_context(|| format!("parse remote rule-set {}", set.tag))
}

pub(crate) fn decode(data: &[u8]) -> Result<Vec<RouteRule>> {
    if data.get(..3) != Some(b"SRS") {
        bail!("invalid sing-box rule-set magic")
    }
    let version = *data.get(3).context("missing sing-box rule-set version")?;
    if version > 4 {
        bail!("unsupported sing-box rule-set version: {version}")
    }
    let mut payload = Vec::new();
    ZlibDecoder::new(&data[4..])
        .read_to_end(&mut payload)
        .context("decompress sing-box rule-set")?;
    let mut reader = Reader::new(&payload);
    let count = reader.uvarint()? as usize;
    (0..count)
        .map(|index| {
            reader
                .rule()
                .with_context(|| format!("read SRS rule[{index}]"))
        })
        .collect()
}

struct Reader<'a> {
    inner: Cursor<&'a [u8]>,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            inner: Cursor::new(data),
        }
    }

    fn byte(&mut self) -> Result<u8> {
        let mut value = [0];
        self.inner.read_exact(&mut value)?;
        Ok(value[0])
    }

    fn bytes(&mut self, length: usize) -> Result<Vec<u8>> {
        let mut value = vec![0; length];
        self.inner.read_exact(&mut value)?;
        Ok(value)
    }

    fn uvarint(&mut self) -> Result<u64> {
        let mut value = 0u64;
        for shift in (0..70).step_by(7) {
            let byte = self.byte()?;
            if byte < 0x80 {
                if shift == 63 && byte > 1 {
                    bail!("SRS integer overflow")
                }
                return Ok(value | u64::from(byte) << shift);
            }
            value |= u64::from(byte & 0x7f) << shift;
        }
        bail!("SRS integer overflow")
    }

    fn strings(&mut self) -> Result<Vec<String>> {
        let count = self.uvarint()? as usize;
        (0..count)
            .map(|_| {
                let length = self.uvarint()? as usize;
                String::from_utf8(self.bytes(length)?).context("invalid UTF-8 in SRS")
            })
            .collect()
    }

    fn u8s(&mut self) -> Result<Vec<u8>> {
        let count = self.uvarint()? as usize;
        self.bytes(count)
    }

    fn u16s(&mut self) -> Result<Vec<u16>> {
        let count = self.uvarint()? as usize;
        (0..count)
            .map(|_| {
                let bytes = self.bytes(2)?;
                Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
            })
            .collect()
    }

    fn rule(&mut self) -> Result<RouteRule> {
        match self.byte()? {
            0 => self.default_rule(),
            1 => {
                let mode = match self.byte()? {
                    0 => "and",
                    1 => "or",
                    value => bail!("unknown SRS logical mode: {value}"),
                };
                let count = self.uvarint()? as usize;
                let rules = (0..count)
                    .map(|_| self.rule())
                    .collect::<Result<Vec<_>>>()?;
                Ok(RouteRule {
                    r#type: "logical".into(),
                    mode: Some(mode.into()),
                    rules,
                    invert: self.byte()? != 0,
                    ..Default::default()
                })
            }
            value => bail!("unknown SRS rule type: {value}"),
        }
    }

    fn default_rule(&mut self) -> Result<RouteRule> {
        let mut rule = RouteRule::default();
        loop {
            match self.byte()? {
                0 => {
                    let _query_types = self.u16s()?;
                }
                1 => rule.network = self.strings()?,
                2 => {
                    let (domain, suffix) = self.domain_matcher()?;
                    rule.domain = domain;
                    rule.domain_suffix = suffix;
                }
                3 => rule.domain_keyword = self.strings()?,
                4 => rule.domain_regex = self.strings()?,
                5 => rule.source_ip_cidr = self.ip_set()?,
                6 => rule.ip_cidr = self.ip_set()?,
                7 => rule.source_port = self.u16s()?,
                8 => rule.source_port_range = self.strings()?,
                9 => rule.port = self.u16s()?,
                10 => rule.port_range = self.strings()?,
                11 => rule.process_name = self.strings()?,
                12 => rule.process_path = self.strings()?,
                13 => rule.package_name = self.strings()?,
                14 => rule.wifi_ssid = self.strings()?,
                15 => rule.wifi_bssid = self.strings()?,
                16 => rule.domain_regex.extend(self.adguard_matcher()?),
                17 => rule.process_path_regex = self.strings()?,
                18 => {
                    rule.network_type = self
                        .u8s()?
                        .into_iter()
                        .map(|value| match value {
                            0 => "wifi".into(),
                            1 => "cellular".into(),
                            2 => "ethernet".into(),
                            3 => "other".into(),
                            _ => value.to_string(),
                        })
                        .collect()
                }
                19 => rule.network_is_expensive = true,
                20 => rule.network_is_constrained = true,
                21 => rule.network_interface_address = self.interface_address_map()?,
                22 => rule.default_interface_address = self.prefixes()?,
                23 => rule.package_name_regex = self.strings()?,
                0xff => {
                    rule.invert = self.byte()? != 0;
                    return Ok(rule);
                }
                value => bail!("unknown SRS rule item: {value}"),
            }
        }
    }

    fn succinct_keys(&mut self) -> Result<Vec<Vec<u8>>> {
        let _reserved = self.byte()?;
        let leaves = self.u64s()?;
        let bitmap = self.u64s()?;
        let labels_length = self.uvarint()? as usize;
        let labels = self.bytes(labels_length)?;
        let mut children: Vec<Vec<(u8, usize)>> = vec![Vec::new()];
        let (mut bit_index, mut label_index, mut node) = (0, 0, 0);
        while node < children.len() {
            while !bit(&bitmap, bit_index) {
                let child = children.len();
                let label = *labels
                    .get(label_index)
                    .context("invalid SRS domain labels")?;
                children[node].push((label, child));
                children.push(Vec::new());
                bit_index += 1;
                label_index += 1;
            }
            bit_index += 1;
            node += 1;
        }
        if label_index != labels.len() {
            bail!("invalid SRS domain tree")
        }
        let mut result = Vec::new();
        collect_keys(0, &children, &leaves, &mut Vec::new(), &mut result);
        Ok(result)
    }

    fn domain_matcher(&mut self) -> Result<(Vec<String>, Vec<String>)> {
        let mut domains = Vec::new();
        let mut suffixes = Vec::new();
        for mut key in self.succinct_keys()? {
            key.reverse();
            match key.first().copied() {
                Some(b'\r' | b'\n') => {
                    key.remove(0);
                    suffixes.push(String::from_utf8(key)?);
                }
                _ => domains.push(String::from_utf8(key)?),
            }
        }
        Ok((domains, suffixes))
    }

    fn adguard_matcher(&mut self) -> Result<Vec<String>> {
        self.succinct_keys()?
            .into_iter()
            .map(|mut key| {
                key.reverse();
                let start = match key.first().copied() {
                    Some(b'\r') => {
                        key.remove(0);
                        String::new()
                    }
                    Some(b'\n') => {
                        key.remove(0);
                        r"(?:^|\.)".into()
                    }
                    _ => "^".into(),
                };
                let end = if key.last() == Some(&b'\x08') {
                    key.pop();
                    String::new()
                } else {
                    "$".into()
                };
                let raw = String::from_utf8(key)?;
                let body = raw
                    .split('*')
                    .map(regex::escape)
                    .collect::<Vec<_>>()
                    .join(".*");
                Ok(format!("{start}{body}{end}"))
            })
            .collect()
    }

    fn u64s(&mut self) -> Result<Vec<u64>> {
        let count = self.uvarint()? as usize;
        (0..count)
            .map(|_| {
                let value = self.bytes(8)?;
                Ok(u64::from_be_bytes(value.try_into().expect("eight bytes")))
            })
            .collect()
    }

    fn ip_set(&mut self) -> Result<Vec<String>> {
        if self.byte()? != 1 {
            bail!("unsupported SRS IP set version")
        }
        let count = u64::from_be_bytes(self.bytes(8)?.try_into().expect("eight bytes"));
        let mut result = Vec::new();
        for _ in 0..count {
            let from_length = self.uvarint()? as usize;
            let from = parse_ip(self.bytes(from_length)?)?;
            let to_length = self.uvarint()? as usize;
            let to = parse_ip(self.bytes(to_length)?)?;
            result.extend(range_to_cidrs(from, to)?);
        }
        Ok(result)
    }

    fn prefix(&mut self) -> Result<String> {
        let length = self.uvarint()? as usize;
        let address = parse_ip(self.bytes(length)?)?;
        let bits = self.byte()?;
        Ok(format!("{address}/{bits}"))
    }

    fn prefixes(&mut self) -> Result<Vec<String>> {
        let count = self.uvarint()? as usize;
        (0..count).map(|_| self.prefix()).collect()
    }

    fn interface_address_map(&mut self) -> Result<std::collections::HashMap<String, Vec<String>>> {
        let count = self.uvarint()? as usize;
        let mut result = std::collections::HashMap::new();
        for _ in 0..count {
            let interface_type = match self.byte()? {
                0 => "wifi".into(),
                1 => "cellular".into(),
                2 => "ethernet".into(),
                3 => "other".into(),
                value => value.to_string(),
            };
            result.insert(interface_type, self.prefixes()?);
        }
        Ok(result)
    }
}

fn bit(words: &[u64], index: usize) -> bool {
    words
        .get(index / 64)
        .is_some_and(|word| word & (1u64 << (index % 64)) != 0)
}

fn collect_keys(
    node: usize,
    children: &[Vec<(u8, usize)>],
    leaves: &[u64],
    key: &mut Vec<u8>,
    result: &mut Vec<Vec<u8>>,
) {
    if bit(leaves, node) {
        result.push(key.clone());
    }
    for &(label, child) in &children[node] {
        key.push(label);
        collect_keys(child, children, leaves, key, result);
        key.pop();
    }
}

fn parse_ip(bytes: Vec<u8>) -> Result<IpAddr> {
    match bytes.as_slice() {
        [a, b, c, d] => Ok(IpAddr::from([*a, *b, *c, *d])),
        bytes if bytes.len() == 16 => Ok(IpAddr::from(
            <[u8; 16]>::try_from(bytes).expect("sixteen bytes"),
        )),
        _ => bail!("invalid IP address length in SRS"),
    }
}

fn range_to_cidrs(from: IpAddr, to: IpAddr) -> Result<Vec<String>> {
    let (mut start, end, width) = match (from, to) {
        (IpAddr::V4(from), IpAddr::V4(to)) => {
            (u128::from(u32::from(from)), u128::from(u32::from(to)), 32)
        }
        (IpAddr::V6(from), IpAddr::V6(to)) => (u128::from(from), u128::from(to), 128),
        _ => bail!("mixed address families in SRS IP range"),
    };
    if start > end {
        bail!("invalid descending SRS IP range")
    }
    let mut result = Vec::new();
    while start <= end {
        let alignment = start.trailing_zeros().min(width);
        let remaining_bits = if end == u128::MAX {
            128
        } else {
            127 - (end - start + 1).leading_zeros()
        };
        let host_bits = alignment.min(remaining_bits);
        let prefix = width - host_bits;
        let address = if width == 32 {
            IpAddr::V4(Ipv4Addr::from(start as u32))
        } else {
            IpAddr::V6(Ipv6Addr::from(start))
        };
        result.push(format!("{address}/{prefix}"));
        if host_bits == 128 {
            break;
        }
        start += 1u128 << host_bits;
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::{
        decode, load_remote_rule_set, range_to_cidrs, rule_set_cache_path, write_rule_set_cache,
    };
    use base64::Engine;
    use std::net::IpAddr;

    #[test]
    fn splits_ip_range_into_prefixes() {
        assert_eq!(
            range_to_cidrs(
                "192.0.2.1".parse::<IpAddr>().unwrap(),
                "192.0.2.6".parse::<IpAddr>().unwrap()
            )
            .unwrap(),
            [
                "192.0.2.1/32",
                "192.0.2.2/31",
                "192.0.2.4/31",
                "192.0.2.6/32"
            ]
        );
    }

    #[test]
    fn decodes_sing_box_generated_binary_rule_set() {
        let binary = base64::engine::general_purpose::STANDARD
            .decode("U1JTAnjaYmJgYmBkAAEhBhCDcW1oyKpVIqk5BbmJFal6JRXJmYlpFWmppcVcbBB1DAxMLAcYmBjBhIACI+8OBiSALsDMxchqYWBlYcjNyJJcWpTzn4GRkYmBmZG1LDMlNf8/AwMjI3NpSsF/BkZAAAAA//80Ahd9")
            .unwrap();
        let rules = decode(&binary).unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].domain, ["exact.example"]);
        assert_eq!(rules[0].domain_suffix, ["suffix.example"]);
        assert_eq!(rules[0].ip_cidr, ["192.0.2.1/32", "2001:db8::/126"]);
        assert_eq!(rules[1].r#type, "logical");
        assert_eq!(rules[1].mode.as_deref(), Some("or"));
        assert!(rules[1].invert);
    }

    #[test]
    fn remote_rule_set_loads_from_disk_cache_first() {
        // Redirect the cache root so the test owns it.
        let cache_dir =
            std::env::temp_dir().join(format!("xhttp-rs-cache-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&cache_dir);
        // SAFETY: single-threaded test; no other code reads this variable.
        unsafe { std::env::set_var("XDG_CACHE_HOME", &cache_dir) };

        let url = "http://127.0.0.1:1/rules.json";
        let set = crate::singbox::RuleSetConfig {
            r#type: "remote".into(),
            tag: "cached".into(),
            format: Some("source".into()),
            url: Some(url.into()),
            ..Default::default()
        };
        let cache_path = rule_set_cache_path(url, "source");
        write_rule_set_cache(
            &cache_path,
            br#"{"rules":[{"domain_suffix":["cached.example"]}]}"#,
        )
        .unwrap();

        // The URL points at an unused port; a cache hit must not touch it.
        let rules = load_remote_rule_set(&set).unwrap();
        assert_eq!(rules.len(), 1);
        let _ = std::fs::remove_dir_all(&cache_dir);
    }
}

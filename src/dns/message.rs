use anyhow::{Context, Result, bail};
use ipnet::IpNet;
use std::net::IpAddr;

use crate::singbox::DnsRule;

pub(super) fn parse_question(request: &[u8]) -> Result<(String, u16, usize)> {
    if request.len() < 12 || u16::from_be_bytes([request[4], request[5]]) == 0 {
        bail!("invalid DNS query")
    }
    let mut position = 12;
    let mut labels = Vec::new();
    loop {
        let length = *request.get(position).context("truncated DNS question")? as usize;
        position += 1;
        if length == 0 {
            break;
        }
        if length > 63 {
            bail!("compressed DNS questions are unsupported")
        }
        let label = request
            .get(position..position + length)
            .context("truncated DNS question label")?;
        labels.push(std::str::from_utf8(label)?.to_owned());
        position += length;
    }
    let fields = request
        .get(position..position + 4)
        .context("truncated DNS question fields")?;
    let qtype = u16::from_be_bytes([fields[0], fields[1]]);
    Ok((normalize(&labels.join(".")), qtype, position + 4))
}

pub(super) async fn local_response(
    request: &[u8],
    name: &str,
    qtype: u16,
    question_end: usize,
) -> Result<Vec<u8>> {
    let addresses: Vec<_> = tokio::net::lookup_host((name, 0))
        .await?
        .map(|address| address.ip())
        .filter(|address| matches!((qtype, address), (1, IpAddr::V4(_)) | (28, IpAddr::V6(_))))
        .collect();
    let mut response = request[..question_end].to_vec();
    response[2] = 0x81;
    response[3] = 0x80;
    response[6..8].copy_from_slice(&(addresses.len() as u16).to_be_bytes());
    response[8..12].fill(0);
    for address in addresses {
        response.extend([0xc0, 0x0c]);
        response.extend(qtype.to_be_bytes());
        response.extend(1u16.to_be_bytes());
        response.extend(30u32.to_be_bytes());
        match address {
            IpAddr::V4(address) => {
                response.extend(4u16.to_be_bytes());
                response.extend(address.octets());
            }
            IpAddr::V6(address) => {
                response.extend(16u16.to_be_bytes());
                response.extend(address.octets());
            }
        }
    }
    Ok(response)
}
pub(super) fn normalize(s: &str) -> String {
    s.trim_end_matches('.').to_ascii_lowercase()
}
pub(super) fn dns_rule_matches(r: &DnsRule, name: &str, qtype: u16) -> bool {
    if r.r#type == "logical" {
        let matched = match r.mode.as_deref().unwrap_or("and") {
            "and" => r
                .rules
                .iter()
                .all(|rule| dns_rule_matches(rule, name, qtype)),
            "or" => r
                .rules
                .iter()
                .any(|rule| dns_rule_matches(rule, name, qtype)),
            _ => false,
        };
        return if r.invert { !matched } else { matched };
    }
    let query_type = r.query_type.is_empty()
        || r.query_type
            .iter()
            .filter_map(|value| parse_query_type(value).ok())
            .any(|value| value == qtype);
    let exact = r.domain.is_empty() || r.domain.iter().any(|v| normalize(v) == name);
    let suffix = r.domain_suffix.is_empty()
        || r.domain_suffix.iter().any(|v| {
            let v = normalize(v);
            name == v || name.ends_with(&format!(".{v}"))
        });
    let keyword = r.domain_keyword.is_empty()
        || r.domain_keyword
            .iter()
            .any(|v| name.contains(&v.to_ascii_lowercase()));
    let regex = r.domain_regex.is_empty()
        || r.domain_regex
            .iter()
            .filter_map(|value| regex::Regex::new(value).ok())
            .any(|value| value.is_match(name));
    let matched = query_type && exact && suffix && keyword && regex;
    if r.invert { !matched } else { matched }
}
pub(super) fn validate_dns_rule(rule: &DnsRule, top_level: bool) -> Result<()> {
    if rule.r#type == "logical" {
        if !matches!(rule.mode.as_deref(), Some("and") | Some("or")) {
            bail!("logical DNS rule requires mode and/or")
        }
        if rule.rules.is_empty() {
            bail!("logical DNS rule requires nested rules")
        }
        for nested in &rule.rules {
            validate_dns_rule(nested, false)?;
        }
    } else if !matches!(rule.r#type.as_str(), "" | "default") {
        bail!("unsupported DNS rule type: {}", rule.r#type)
    }
    for value in &rule.domain_regex {
        regex::Regex::new(value).with_context(|| format!("invalid DNS domain_regex: {value}"))?;
    }
    for value in &rule.query_type {
        parse_query_type(value)?;
    }
    if !top_level
        && rule
            .action
            .as_deref()
            .is_some_and(|action| !action.is_empty())
    {
        bail!("nested logical DNS rules cannot contain actions")
    }
    if !matches!(
        rule.action.as_deref(),
        None | Some("") | Some("route") | Some("reject")
    ) {
        bail!(
            "unsupported DNS rule action: {}",
            rule.action.as_deref().unwrap()
        )
    }
    if rule.action.as_deref() == Some("reject")
        && !matches!(
            rule.method.as_deref(),
            None | Some("") | Some("default") | Some("drop")
        )
    {
        bail!(
            "unsupported DNS reject method: {}",
            rule.method.as_deref().unwrap()
        )
    }
    if let Some(subnet) = &rule.client_subnet {
        parse_client_subnet(subnet)?;
    }
    validate_strategy(rule.strategy.as_deref())
}
pub(super) fn parse_query_type(value: &serde_json::Value) -> Result<u16> {
    if let Some(value) = value.as_u64() {
        return value
            .try_into()
            .context("DNS query_type number exceeds 65535");
    }
    let value = value
        .as_str()
        .context("DNS query_type must be a number or string")?;
    if let Ok(value) = value.parse() {
        return Ok(value);
    }
    Ok(match value.to_ascii_uppercase().as_str() {
        "A" => 1,
        "NS" => 2,
        "CNAME" => 5,
        "SOA" => 6,
        "PTR" => 12,
        "MX" => 15,
        "TXT" => 16,
        "AAAA" => 28,
        "SRV" => 33,
        "OPT" => 41,
        "SVCB" => 64,
        "HTTPS" => 65,
        "CAA" => 257,
        _ => bail!("unsupported DNS query_type name: {value}"),
    })
}
pub(super) fn build_query(id: u16, name: &str, qtype: u16) -> Result<Vec<u8>> {
    build_query_with_subnet(id, name, qtype, None)
}
pub(super) fn build_query_with_subnet(
    id: u16,
    name: &str,
    qtype: u16,
    client_subnet: Option<&str>,
) -> Result<Vec<u8>> {
    let mut b = Vec::with_capacity(64);
    b.extend(id.to_be_bytes());
    b.extend([1, 0, 0, 1, 0, 0, 0, 0, 0, u8::from(client_subnet.is_some())]);
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 {
            bail!("invalid DNS name")
        };
        b.push(label.len() as u8);
        b.extend(label.as_bytes())
    }
    b.push(0);
    b.extend(qtype.to_be_bytes());
    b.extend(1u16.to_be_bytes());
    if let Some(subnet) = client_subnet {
        append_client_subnet_opt(&mut b, subnet)?;
    }
    Ok(b)
}
pub(super) fn add_client_subnet(request: &[u8], subnet: &str) -> Result<Vec<u8>> {
    if request.len() < 12 {
        bail!("invalid DNS query")
    }
    if u16::from_be_bytes([request[10], request[11]]) != 0 {
        bail!("DNS client_subnet cannot be added to a query that already has additional records")
    }
    let mut wire = request.to_vec();
    wire[10..12].copy_from_slice(&1u16.to_be_bytes());
    append_client_subnet_opt(&mut wire, subnet)?;
    Ok(wire)
}
pub(super) fn append_client_subnet_opt(output: &mut Vec<u8>, subnet: &str) -> Result<()> {
    let subnet = parse_client_subnet(subnet)?;
    let (family, prefix, address) = match subnet {
        IpNet::V4(network) => (
            1u16,
            network.prefix_len(),
            network.network().octets().to_vec(),
        ),
        IpNet::V6(network) => (
            2u16,
            network.prefix_len(),
            network.network().octets().to_vec(),
        ),
    };
    let address_length = usize::from(prefix).div_ceil(8);
    let option_length: u16 = (4 + address_length)
        .try_into()
        .context("EDNS client subnet option is too large")?;
    output.push(0);
    output.extend(41u16.to_be_bytes());
    output.extend(1232u16.to_be_bytes());
    output.extend(0u32.to_be_bytes());
    output.extend((4u16 + option_length).to_be_bytes());
    output.extend(8u16.to_be_bytes());
    output.extend(option_length.to_be_bytes());
    output.extend(family.to_be_bytes());
    output.push(prefix);
    output.push(0);
    output.extend(&address[..address_length]);
    Ok(())
}
pub(super) fn refused_response(request: &[u8], question_end: usize) -> Result<Vec<u8>> {
    let mut response = request
        .get(..question_end)
        .context("truncated DNS question")?
        .to_vec();
    response[2] |= 0x80;
    response[3] = (response[3] & 0xf0) | 5;
    response[6..12].fill(0);
    Ok(response)
}
pub(super) fn parse_client_subnet(value: &str) -> Result<IpNet> {
    value
        .parse::<IpNet>()
        .or_else(|_| {
            value.parse::<IpAddr>().map(|address| match address {
                IpAddr::V4(address) => IpNet::new(address.into(), 32).expect("valid IPv4 prefix"),
                IpAddr::V6(address) => IpNet::new(address.into(), 128).expect("valid IPv6 prefix"),
            })
        })
        .with_context(|| format!("invalid DNS client_subnet: {value}"))
}
pub(super) fn validate_strategy(strategy: Option<&str>) -> Result<()> {
    if matches!(
        strategy,
        None | Some("")
            | Some("prefer_ipv4")
            | Some("prefer_ipv6")
            | Some("ipv4_only")
            | Some("ipv6_only")
    ) {
        Ok(())
    } else {
        bail!("unsupported DNS strategy: {}", strategy.unwrap())
    }
}
pub(super) fn optimistic_enabled(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Bool(enabled) => *enabled,
        serde_json::Value::Object(options) => options
            .get("enabled")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(true),
        serde_json::Value::Null => false,
        _ => true,
    }
}
pub(super) fn dns_id(message: &[u8]) -> Result<u16> {
    let bytes = message.get(..2).context("truncated DNS message")?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}
pub(super) fn canonical_query(request: &[u8]) -> Vec<u8> {
    let mut key = request.to_vec();
    if key.len() >= 2 {
        key[..2].fill(0);
    }
    key
}
pub(super) fn validate_response(expected_id: u16, response: &[u8]) -> Result<()> {
    if response.len() < 12 {
        bail!("truncated DNS response")
    }
    if dns_id(response)? != expected_id {
        bail!("DNS response transaction ID mismatch")
    }
    if response[2] & 0x80 == 0 {
        bail!("DNS message is not a response")
    }
    Ok(())
}
pub(super) fn response_ttl(response: &[u8]) -> u32 {
    ttl_offsets(response)
        .ok()
        .and_then(|offsets| {
            offsets
                .into_iter()
                .filter(|(_, record_type, _)| *record_type != 41)
                .map(|(_, _, ttl)| ttl)
                .min()
        })
        .unwrap_or(30)
}
pub(super) fn age_response_ttls(response: &mut [u8], elapsed: u32) {
    let Ok(offsets) = ttl_offsets(response) else {
        return;
    };
    for (offset, record_type, ttl) in offsets {
        if record_type != 41 {
            response[offset..offset + 4]
                .copy_from_slice(&ttl.saturating_sub(elapsed).to_be_bytes());
        }
    }
}
pub(super) fn rewrite_response_ttls(response: &mut [u8], replacement: u32) {
    let Ok(offsets) = ttl_offsets(response) else {
        return;
    };
    for (offset, record_type, _) in offsets {
        if record_type != 41 {
            response[offset..offset + 4].copy_from_slice(&replacement.to_be_bytes());
        }
    }
}
pub(super) fn ttl_offsets(message: &[u8]) -> Result<Vec<(usize, u16, u32)>> {
    if message.len() < 12 {
        bail!("truncated DNS message")
    }
    let questions = u16::from_be_bytes([message[4], message[5]]) as usize;
    let records = u16::from_be_bytes([message[6], message[7]]) as usize
        + u16::from_be_bytes([message[8], message[9]]) as usize
        + u16::from_be_bytes([message[10], message[11]]) as usize;
    let mut position = 12;
    for _ in 0..questions {
        skip_name(message, &mut position)?;
        position = position
            .checked_add(4)
            .filter(|value| *value <= message.len())
            .context("truncated DNS question")?;
    }
    let mut offsets = Vec::with_capacity(records);
    for _ in 0..records {
        skip_name(message, &mut position)?;
        let header = message
            .get(position..position + 10)
            .context("truncated DNS record")?;
        let record_type = u16::from_be_bytes([header[0], header[1]]);
        let ttl = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);
        let length = u16::from_be_bytes([header[8], header[9]]) as usize;
        offsets.push((position + 4, record_type, ttl));
        position = position
            .checked_add(10 + length)
            .filter(|value| *value <= message.len())
            .context("truncated DNS record data")?;
    }
    Ok(offsets)
}
pub(super) fn parse_response(id: u16, qtype: u16, b: &[u8]) -> Result<(Vec<IpAddr>, u32)> {
    if b.len() < 12 || u16::from_be_bytes([b[0], b[1]]) != id {
        bail!("invalid DNS response")
    };
    let flags = u16::from_be_bytes([b[2], b[3]]);
    if flags & 0x8000 == 0 || flags & 15 != 0 {
        bail!("DNS error rcode {}", flags & 15)
    }
    let qd = u16::from_be_bytes([b[4], b[5]]) as usize;
    let an = u16::from_be_bytes([b[6], b[7]]) as usize;
    let mut p = 12;
    for _ in 0..qd {
        skip_name(b, &mut p)?;
        p = p
            .checked_add(4)
            .filter(|v| *v <= b.len())
            .context("truncated DNS question")?
    }
    let mut out = Vec::new();
    let mut ttl = u32::MAX;
    for _ in 0..an {
        skip_name(b, &mut p)?;
        if p + 10 > b.len() {
            bail!("truncated DNS answer")
        };
        let typ = u16::from_be_bytes([b[p], b[p + 1]]);
        let record_ttl = u32::from_be_bytes([b[p + 4], b[p + 5], b[p + 6], b[p + 7]]);
        let len = u16::from_be_bytes([b[p + 8], b[p + 9]]) as usize;
        p += 10;
        if p + len > b.len() {
            bail!("truncated DNS rdata")
        };
        if typ == qtype {
            match (typ, len) {
                (1, 4) => out.push(IpAddr::from([b[p], b[p + 1], b[p + 2], b[p + 3]])),
                (28, 16) => {
                    let mut a = [0; 16];
                    a.copy_from_slice(&b[p..p + 16]);
                    out.push(IpAddr::from(a))
                }
                _ => {}
            }
            ttl = ttl.min(record_ttl)
        }
        p += len
    }
    Ok((out, if ttl == u32::MAX { 30 } else { ttl }))
}
pub(super) fn parse_https_ech(id: u16, message: &[u8]) -> Result<Vec<u8>> {
    if message.len() < 12 || dns_id(message)? != id {
        bail!("invalid DNS HTTPS response")
    }
    let flags = u16::from_be_bytes([message[2], message[3]]);
    if flags & 0x8000 == 0 || flags & 15 != 0 {
        bail!("DNS HTTPS error rcode {}", flags & 15)
    }
    let questions = u16::from_be_bytes([message[4], message[5]]) as usize;
    let answers = u16::from_be_bytes([message[6], message[7]]) as usize;
    let mut position = 12;
    for _ in 0..questions {
        skip_name(message, &mut position)?;
        position = position
            .checked_add(4)
            .filter(|value| *value <= message.len())
            .context("truncated DNS HTTPS question")?;
    }
    for _ in 0..answers {
        skip_name(message, &mut position)?;
        let header = message
            .get(position..position + 10)
            .context("truncated DNS HTTPS answer")?;
        let record_type = u16::from_be_bytes([header[0], header[1]]);
        let length = u16::from_be_bytes([header[8], header[9]]) as usize;
        position += 10;
        let end = position
            .checked_add(length)
            .filter(|value| *value <= message.len())
            .context("truncated DNS HTTPS record data")?;
        if record_type != 65 {
            position = end;
            continue;
        }
        position = position
            .checked_add(2)
            .filter(|value| *value <= end)
            .context("truncated DNS HTTPS priority")?;
        skip_name(message, &mut position)?;
        if position > end {
            bail!("DNS HTTPS target exceeds record")
        }
        while position < end {
            let parameter = message
                .get(position..position + 4)
                .context("truncated DNS HTTPS parameter")?;
            let key = u16::from_be_bytes([parameter[0], parameter[1]]);
            let value_length = u16::from_be_bytes([parameter[2], parameter[3]]) as usize;
            position += 4;
            let value_end = position
                .checked_add(value_length)
                .filter(|value| *value <= end)
                .context("truncated DNS HTTPS parameter value")?;
            if key == 5 {
                if value_length == 0 {
                    bail!("empty ECH config in DNS HTTPS record")
                }
                return Ok(message[position..value_end].to_vec());
            }
            position = value_end;
        }
        position = end;
    }
    bail!("no ECH config found in DNS HTTPS records")
}
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub fn fuzz_dns_message(input: &[u8]) {
    let id = input
        .get(..2)
        .map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]))
        .unwrap_or(0);
    for qtype in [1, 28] {
        let _ = parse_response(id, qtype, input);
    }
}
pub(super) fn skip_name(b: &[u8], p: &mut usize) -> Result<()> {
    let mut count = 0;
    loop {
        if *p >= b.len() {
            bail!("truncated DNS name")
        };
        let n = b[*p];
        *p += 1;
        if n == 0 {
            return Ok(());
        }
        if n & 0xc0 == 0xc0 {
            if *p >= b.len() {
                bail!("truncated DNS pointer")
            };
            *p += 1;
            return Ok(());
        }
        if n & 0xc0 != 0 || n > 63 {
            bail!("invalid DNS label")
        };
        *p += n as usize;
        if *p > b.len() {
            bail!("truncated DNS label")
        };
        count += 1;
        if count > 127 {
            bail!("invalid DNS name")
        }
    }
}

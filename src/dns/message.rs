use anyhow::{Context, Result, bail};
use ipnet::IpNet;
use std::{collections::HashMap, net::IpAddr};

use crate::routing::CompiledRule;
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
pub(super) fn dns_rule_matches(
    r: &DnsRule,
    name: &str,
    qtype: u16,
    rule_sets: Option<&HashMap<String, Vec<CompiledRule>>>,
) -> bool {
    if r.r#type == "logical" {
        let matched = match r.mode.as_deref().unwrap_or("and") {
            "and" => r
                .rules
                .iter()
                .all(|rule| dns_rule_matches(rule, name, qtype, rule_sets)),
            "or" => r
                .rules
                .iter()
                .any(|rule| dns_rule_matches(rule, name, qtype, rule_sets)),
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
    let rule_set = r.rule_set.is_empty()
        || rule_sets.is_some_and(|sets| {
            r.rule_set.iter().any(|tag| {
                sets.get(tag).is_some_and(|rules| {
                    rules
                        .iter()
                        .any(|rule| rule.dns_matches_domain(name) || rule.dns_contains_ip_cidr())
                })
            })
        });
    let matched = query_type && exact && suffix && keyword && regex && rule_set;
    if r.invert { !matched } else { matched }
}

/// The IP CIDR constraints of a rule's rule-sets, used to reject DNS
/// responses whose addresses fall outside them (sing-box `WithAddressLimit`).
pub(super) fn dns_rule_has_address_limit(
    r: &DnsRule,
    rule_sets: Option<&HashMap<String, Vec<CompiledRule>>>,
) -> bool {
    if r.r#type == "logical" {
        return r
            .rules
            .iter()
            .any(|rule| dns_rule_has_address_limit(rule, rule_sets));
    }
    rule_sets.is_some_and(|sets| {
        r.rule_set.iter().any(|tag| {
            sets.get(tag)
                .is_some_and(|rules| rules.iter().any(|rule| rule.dns_contains_ip_cidr()))
        })
    })
}

/// Post-resolution response check: every address in `addresses` must match
/// the rule's address limits, mirroring sing-box `MatchAddressLimit`.
pub(super) fn dns_rule_address_limit_matches(
    r: &DnsRule,
    name: &str,
    addresses: &[IpAddr],
    rule_sets: Option<&HashMap<String, Vec<CompiledRule>>>,
) -> bool {
    if r.r#type == "logical" {
        let matched = match r.mode.as_deref().unwrap_or("and") {
            "and" => r.rules.iter().all(|rule| {
                dns_rule_address_limit_matches(rule, name, addresses, rule_sets)
            }),
            "or" => r.rules.iter().any(|rule| {
                dns_rule_address_limit_matches(rule, name, addresses, rule_sets)
            }),
            _ => false,
        };
        return if r.invert { !matched } else { matched };
    }
    let sets_matched = rule_sets.is_none_or(|sets| {
        r.rule_set.iter().any(|tag| {
            sets.get(tag).is_some_and(|rules| {
                rules
                    .iter()
                    .any(|rule| {
                        addresses
                            .iter()
                            .any(|address| rule.dns_matches_address(*address, Some(name)))
                    })
            })
        })
    });
    if r.invert { !sets_matched } else { sets_matched }
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
        None | Some("") | Some("route") | Some("reject") | Some("predefined")
    ) {
        bail!(
            "unsupported DNS rule action: {}",
            rule.action.as_deref().unwrap()
        )
    }
    if rule.action.as_deref() == Some("predefined") {
        parse_rcode(rule.rcode.as_ref())?;
        for record in rule
            .answer
            .iter()
            .chain(&rule.ns)
            .chain(&rule.extra)
        {
            parse_dns_record(record)?;
        }
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

/// One parsed resource record from a `predefined` DNS rule answer/ns/extra
/// entry, encoded ready for insertion into a response.
#[derive(Debug, Clone)]
pub(super) struct PredefinedRecord {
    pub(super) owner: String,
    pub(super) ttl: u32,
    pub(super) kind: u16,
    pub(super) rdata: Vec<u8>,
}

pub(super) fn parse_rcode(value: Option<&serde_json::Value>) -> Result<u8> {
    let Some(value) = value else {
        return Ok(0);
    };
    if let Some(number) = value.as_u64() {
        return u8::try_from(number).context("DNS rcode exceeds 255");
    }
    let value = value.as_str().context("DNS rcode must be a number or string")?;
    Ok(match value {
        "NOERROR" => 0,
        "FORMERR" => 1,
        "SERVFAIL" => 2,
        "NXDOMAIN" => 3,
        "NOTIMP" => 4,
        "REFUSED" => 5,
        _ => bail!("unsupported DNS rcode: {value}"),
    })
}

/// Parse a text resource record such as `. 2147483647 IN A 0.0.0.0` or
/// `localhost. IN TXT "Hello"` into an encoded record. The owner name is
/// kept verbatim; `*`-prefixed owners are resolved against the query name
/// when the response is built, matching sing-box behavior.
pub(super) fn parse_dns_record(record: &str) -> Result<PredefinedRecord> {
    let mut tokens = record.split_whitespace();
    let owner = tokens
        .next()
        .context("empty DNS record")?
        .trim_end_matches('.')
        .to_owned();
    let (ttl, mut tokens): (u32, Box<dyn Iterator<Item = &str>>) = {
        let mut iter = tokens;
        let first = iter.next().context("DNS record is missing fields")?;
        match first.parse::<u32>() {
            Ok(ttl) => (ttl, Box::new(iter)),
            Err(_) if matches!(
                first,
                "IN" | "CH" | "HS" | "A" | "AAAA" | "CNAME" | "NS" | "PTR" | "MX" | "SOA"
                    | "TXT" | "SRV" | "CAA"
            ) => (3600, Box::new(std::iter::once(first).chain(iter))),
            Err(_) => bail!("invalid DNS record TTL: {first}"),
        }
    };
    let class = tokens.next().context("DNS record is missing a class")?;
    if !matches!(class, "IN") {
        bail!("unsupported DNS record class: {class}")
    }
    let kind = tokens.next().context("DNS record is missing a type")?;
    let rdata = match kind {
        "A" => {
            let address: IpAddr = tokens
                .next()
                .context("A record is missing an address")?
                .parse()
                .context("invalid A record address")?;
            let IpAddr::V4(address) = address else {
                bail!("A record requires an IPv4 address")
            };
            address.octets().to_vec()
        }
        "AAAA" => {
            let address: IpAddr = tokens
                .next()
                .context("AAAA record is missing an address")?
                .parse()
                .context("invalid AAAA record address")?;
            let IpAddr::V6(address) = address else {
                bail!("AAAA record requires an IPv6 address")
            };
            address.octets().to_vec()
        }
        "CNAME" | "NS" | "PTR" => encode_name(tokens.next().context("record is missing a name")?)?,
        "TXT" => {
            let mut data = Vec::new();
            for text in tokens {
                let text = text.trim_matches('"');
                if text.len() > 255 {
                    bail!("TXT record string exceeds 255 bytes")
                }
                data.push(text.len() as u8);
                data.extend_from_slice(text.as_bytes());
            }
            if data.is_empty() {
                bail!("TXT record requires at least one string")
            }
            data
        }
        "MX" => {
            let preference: u16 = tokens
                .next()
                .context("MX record is missing a preference")?
                .parse()
                .context("invalid MX preference")?;
            let mut data = preference.to_be_bytes().to_vec();
            data.extend(encode_name(tokens.next().context("MX record is missing an exchange")?)?);
            data
        }
        "SOA" => {
            let mname = encode_name(tokens.next().context("SOA record is missing mname")?)?;
            let rname = encode_name(tokens.next().context("SOA record is missing rname")?)?;
            let mut data = mname;
            data.extend(rname);
            for _ in 0..5 {
                let value: u32 = tokens
                    .next()
                    .context("SOA record is missing a numeric field")?
                    .parse()
                    .context("invalid SOA numeric field")?;
                data.extend(value.to_be_bytes());
            }
            data
        }
        "SRV" => {
            let mut data = Vec::new();
            for _ in 0..3 {
                let value: u16 = tokens
                    .next()
                    .context("SRV record is missing a numeric field")?
                    .parse()
                    .context("invalid SRV numeric field")?;
                data.extend(value.to_be_bytes());
            }
            data.extend(encode_name(tokens.next().context("SRV record is missing a target")?)?);
            data
        }
        "CAA" => {
            let flags: u8 = tokens
                .next()
                .context("CAA record is missing flags")?
                .parse()
                .context("invalid CAA flags")?;
            let tag = tokens.next().context("CAA record is missing a tag")?;
            let value = tokens.next().context("CAA record is missing a value")?;
            let mut data = vec![flags, tag.len() as u8];
            data.extend_from_slice(tag.as_bytes());
            data.extend_from_slice(value.trim_matches('"').as_bytes());
            data
        }
        _ => bail!("unsupported DNS record type: {kind}"),
    };
    let kind = match kind {
        "A" => 1,
        "NS" => 2,
        "CNAME" => 5,
        "SOA" => 6,
        "PTR" => 12,
        "MX" => 15,
        "TXT" => 16,
        "AAAA" => 28,
        "SRV" => 33,
        "CAA" => 257,
        _ => unreachable!("record type was validated"),
    };
    Ok(PredefinedRecord {
        owner,
        ttl,
        kind,
        rdata,
    })
}

fn encode_name(name: &str) -> Result<Vec<u8>> {
    let name = name.trim_end_matches('.');
    if name.is_empty() {
        return Ok(vec![0]);
    }
    let mut out = Vec::with_capacity(name.len() + 2);
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 {
            bail!("invalid DNS record name: {name}")
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    Ok(out)
}

/// Build a `predefined` rule response: the request's question is echoed and
/// the configured records are inserted. `*`-prefixed owners are replaced by
/// the query name when the query name ends with the remainder, matching
/// sing-box `rewriteRecords`.
pub(super) fn predefined_response(
    request: &[u8],
    question_end: usize,
    rcode: u8,
    records: &[PredefinedRecord],
) -> Result<Vec<u8>> {
    let (query_name, _, _) = parse_question(request)?;
    let mut response = request
        .get(..question_end)
        .context("truncated DNS question")?
        .to_vec();
    response[2] = 0x80 | 0x04 | 0x01; // QR, AA, RD
    response[3] = 0x80 | (rcode & 0x0f); // RA, rcode
    response[6..12].fill(0);
    let mut written = 0u16;
    for record in records {
        let owner = if let Some(remainder) = record.owner.strip_prefix('*') {
            let remainder = remainder.trim_start_matches('.');
            if remainder.is_empty() || query_name.ends_with(&format!(".{remainder}")) {
                query_name.clone()
            } else {
                continue;
            }
        } else {
            record.owner.clone()
        };
        response.extend(encode_name(&owner)?);
        response.extend(record.kind.to_be_bytes());
        response.extend(1u16.to_be_bytes()); // IN
        response.extend(record.ttl.to_be_bytes());
        response.extend((record.rdata.len() as u16).to_be_bytes());
        response.extend(&record.rdata);
        written += 1;
    }
    response[6..8].copy_from_slice(&written.to_be_bytes());
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

#[cfg(test)]
mod tests {
    use super::*;

    fn question(name: &str, qtype: u16) -> Vec<u8> {
        let mut query = vec![0u8; 12];
        query[2] = 1;
        query[4..6].copy_from_slice(&1u16.to_be_bytes());
        for label in name.split('.') {
            query.push(label.len() as u8);
            query.extend_from_slice(label.as_bytes());
        }
        query.push(0);
        query.extend(qtype.to_be_bytes());
        query.extend(1u16.to_be_bytes());
        query
    }

    #[test]
    fn parse_question_extracts_name_type_and_end() {
        let query = question("www.example.com", 1);
        let (name, qtype, end) = parse_question(&query).unwrap();
        assert_eq!(name, "www.example.com");
        assert_eq!(qtype, 1);
        assert_eq!(&query[12..end], &query[12..]);
        assert!(parse_question(&[0u8; 4]).is_err());
        assert!(parse_question(&[0u8; 12]).is_err()); // zero questions
    }

    #[test]
    fn parse_question_rejects_compression_and_long_labels() {
        let mut compressed = vec![0u8; 12];
        compressed[4..6].copy_from_slice(&1u16.to_be_bytes());
        compressed.push(0xc0);
        compressed.push(0x0c);
        assert!(parse_question(&compressed).is_err());

        let mut long = vec![0u8; 12];
        long[4..6].copy_from_slice(&1u16.to_be_bytes());
        long.push(64); // label length 64 > 63
        assert!(parse_question(&long).is_err());
    }

    #[test]
    fn build_query_round_trips_through_parse_question() {
        let query = build_query(7, "example.com", 28).unwrap();
        assert_eq!(&query[..2], &7u16.to_be_bytes());
        let (name, qtype, _) = parse_question(&query).unwrap();
        assert_eq!(name, "example.com");
        assert_eq!(qtype, 28);
    }

    #[test]
    fn build_query_with_subnet_appends_edns_option() {
        let query = build_query_with_subnet(1, "example.com", 1, Some("192.0.2.0/24")).unwrap();
        assert_eq!(&query[10..12], &1u16.to_be_bytes()); // ARCOUNT
        assert!(query.ends_with(&[
            0, 0, 41, 4, 208, // EDNS root
            0, 0, 0, 0, // extended rcode, version, DO, Z
            0, 11, // option length
            0, 8, // option code client subnet
            0, 7, // option data length
            0, 1, 24, 0, 192, 0, 2,
        ]));
        assert!(build_query(1, "bad..name", 1).is_err());
    }

    #[test]
    fn add_client_subnet_validates_empty_additional_records() {
        let query = build_query(1, "example.com", 1).unwrap();
        let modified = add_client_subnet(&query, "2001:db8::/32").unwrap();
        assert_eq!(&modified[10..12], &1u16.to_be_bytes());
        let mut with_additional = query.clone();
        with_additional[10..12].copy_from_slice(&1u16.to_be_bytes());
        assert!(add_client_subnet(&with_additional, "192.0.2.0/24").is_err());
    }

    #[test]
    fn parse_client_subnet_accepts_network_and_single_address() {
        assert!(parse_client_subnet("192.0.2.0/24").is_ok());
        assert!(parse_client_subnet("2001:db8::/32").is_ok());
        let single = parse_client_subnet("10.0.0.1").unwrap();
        assert_eq!(single.prefix_len(), 32);
        assert!(parse_client_subnet("not-an-ip").is_err());
    }

    #[test]
    fn refused_response_preserves_question_and_sets_rcode() {
        let query = question("example.com", 1);
        let (_, _, question_end) = parse_question(&query).unwrap();
        let response = refused_response(&query, question_end).unwrap();
        assert_eq!(&response[..2], &query[..2]);
        assert_ne!(response[2] & 0x80, 0);
        assert_eq!(response[3] & 0x0f, 5);
        assert_eq!(&response[6..12], &[0, 0, 0, 0, 0, 0]);
        assert_eq!(&response[12..], &query[12..question_end]);
    }

    #[test]
    fn dns_id_and_canonical_query_round_trip() {
        let query = build_query(42, "example.com", 1).unwrap();
        assert_eq!(dns_id(&query).unwrap(), 42);
        let canonical = canonical_query(&query);
        assert_eq!(&canonical[..2], &[0, 0]);
        assert_eq!(&canonical[2..], &query[2..]);
    }

    #[test]
    fn validate_response_checks_id_and_flags() {
        let mut response = build_query(7, "example.com", 1).unwrap();
        response[2] = 0x81; // response flag
        assert!(validate_response(7, &response).is_ok());
        assert!(validate_response(8, &response).is_err()); // id mismatch
        response[2] = 0x01; // not a response
        assert!(validate_response(7, &response).is_err());
        assert!(validate_response(7, &[0u8; 4]).is_err()); // truncated
    }

    #[test]
    fn ttl_offsets_and_rewrite_visit_only_records() {
        let mut response = build_query(1, "example.com", 1).unwrap();
        response[2] = 0x81;
        response[3] = 0x80;
        response[6..8].copy_from_slice(&1u16.to_be_bytes()); // ANCOUNT
        response.extend([0xc0, 0x0c]);
        response.extend(1u16.to_be_bytes()); // A
        response.extend(1u16.to_be_bytes()); // class
        response.extend(300u32.to_be_bytes()); // ttl
        response.extend(4u16.to_be_bytes()); // rdlength
        response.extend([1, 2, 3, 4]);

        let offsets = ttl_offsets(&response).unwrap();
        assert_eq!(offsets.len(), 1);
        assert_eq!(offsets[0].1, 1); // record type A
        assert_eq!(offsets[0].2, 300); // ttl
        assert_eq!(response_ttl(&response), 300);

        rewrite_response_ttls(&mut response, 60);
        assert_eq!(response_ttl(&response), 60);
        age_response_ttls(&mut response, 10);
        assert_eq!(response_ttl(&response), 50);
    }

    #[test]
    fn parse_response_extracts_matching_addresses_and_ttl() {
        let mut response = build_query(1, "example.com", 1).unwrap();
        response[2] = 0x81;
        response[3] = 0x80;
        response[6..8].copy_from_slice(&2u16.to_be_bytes()); // ANCOUNT
        response.extend([0xc0, 0x0c]);
        response.extend(1u16.to_be_bytes());
        response.extend(1u16.to_be_bytes());
        response.extend(60u32.to_be_bytes());
        response.extend(4u16.to_be_bytes());
        response.extend([10, 0, 0, 1]);
        response.extend([0xc0, 0x0c]);
        response.extend(28u16.to_be_bytes()); // AAAA, does not match qtype
        response.extend(1u16.to_be_bytes());
        response.extend(120u32.to_be_bytes());
        response.extend(16u16.to_be_bytes());
        response.extend([0u8; 16]);

        let (addresses, ttl) = parse_response(1, 1, &response).unwrap();
        assert_eq!(addresses, vec!["10.0.0.1".parse::<IpAddr>().unwrap()]);
        assert_eq!(ttl, 60);
    }

    #[test]
    fn skip_name_handles_labels_pointers_and_errors() {
        // name occupies bytes 0..13: \x07example \x03com \x00
        let data = b"\x07example\x03com\x00\xc0\x0c";
        let mut position = 0;
        assert!(skip_name(data, &mut position).is_ok());
        assert_eq!(position, 13);
        // A compression pointer advances by two bytes.
        let mut pointer_position = 13;
        assert!(skip_name(data, &mut pointer_position).is_ok());
        assert_eq!(pointer_position, 15);
        assert!(skip_name(&[0u8; 0], &mut 0).is_err()); // empty
        let mut pos = 0;
        let long = [0x40u8]; // label length 64 invalid
        assert!(skip_name(&long, &mut pos).is_err());
        // A label whose length runs past the buffer is truncated.
        let mut pos = 0;
        let truncated = [0x05u8, b'a'];
        assert!(skip_name(&truncated, &mut pos).is_err());
    }

    #[test]
    fn parse_query_type_accepts_numbers_and_names() {
        assert_eq!(parse_query_type(&serde_json::json!(1)).unwrap(), 1);
        assert_eq!(parse_query_type(&serde_json::json!("AAAA")).unwrap(), 28);
        assert_eq!(parse_query_type(&serde_json::json!("HTTPS")).unwrap(), 65);
        assert!(parse_query_type(&serde_json::json!(70000)).unwrap_err().to_string().contains("65535"));
        assert!(parse_query_type(&serde_json::json!("BOGUS")).is_err());
    }

    #[test]
    fn validate_strategy_accepts_known_and_rejects_unknown() {
        assert!(validate_strategy(None).is_ok());
        assert!(validate_strategy(Some("prefer_ipv4")).is_ok());
        assert!(validate_strategy(Some("ipv6_only")).is_ok());
        assert!(validate_strategy(Some("random")).is_err());
    }

    #[test]
    fn parse_rcode_accepts_names_and_numbers() {
        assert_eq!(parse_rcode(None).unwrap(), 0);
        assert_eq!(parse_rcode(Some(&serde_json::json!("NOERROR"))).unwrap(), 0);
        assert_eq!(parse_rcode(Some(&serde_json::json!("NXDOMAIN"))).unwrap(), 3);
        assert_eq!(parse_rcode(Some(&serde_json::json!("REFUSED"))).unwrap(), 5);
        assert_eq!(parse_rcode(Some(&serde_json::json!(2))).unwrap(), 2);
        assert!(parse_rcode(Some(&serde_json::json!("BOGUS"))).is_err());
        assert!(parse_rcode(Some(&serde_json::json!(300))).is_err());
    }

    #[test]
    fn parse_dns_record_handles_ttl_class_and_common_types() {
        let record = parse_dns_record(". 2147483647 IN A 0.0.0.0").unwrap();
        assert_eq!(record.owner, "");
        assert_eq!(record.ttl, 2147483647);
        assert_eq!(record.kind, 1);
        assert_eq!(record.rdata, vec![0, 0, 0, 0]);

        let record = parse_dns_record("localhost. IN A 127.0.0.1").unwrap();
        assert_eq!(record.owner, "localhost");
        assert_eq!(record.ttl, 3600);
        assert_eq!(record.kind, 1);
        assert_eq!(record.rdata, vec![127, 0, 0, 1]);

        let record = parse_dns_record("example.com. 60 IN AAAA ::1").unwrap();
        assert_eq!(record.ttl, 60);
        assert_eq!(record.kind, 28);
        let mut expected = [0u8; 16];
        expected[15] = 1;
        assert_eq!(record.rdata, expected);

        let record = parse_dns_record("a.example. IN TXT \"Hello\"").unwrap();
        assert_eq!(record.kind, 16);
        assert_eq!(record.rdata, vec![5, b'H', b'e', b'l', b'l', b'o']);

        let record = parse_dns_record("m.example. IN MX 10 mail.example.").unwrap();
        assert_eq!(record.kind, 15);
        assert_eq!(&record.rdata[..2], &10u16.to_be_bytes());
        assert_eq!(&record.rdata[2..], &encode_name("mail.example").unwrap());

        assert!(parse_dns_record("bogus").is_err());
        assert!(parse_dns_record("a. 60 CH A 1.2.3.4").is_err());
        assert!(parse_dns_record("a. 60 IN BOGUS x").is_err());
        assert!(parse_dns_record("a. 60 IN A 300.1.1.1").is_err());
    }

    #[test]
    fn predefined_response_echoes_question_and_rewrites_wildcard_owners() {
        let query = question("ads.example.com", 1);
        let (_, _, question_end) = parse_question(&query).unwrap();
        let records = vec![
            parse_dns_record(". 60 IN A 0.0.0.0").unwrap(),
            parse_dns_record("*.example.com 60 IN A 0.0.0.0").unwrap(),
            parse_dns_record("*.elsewhere.net 60 IN A 0.0.0.0").unwrap(),
        ];
        let response = predefined_response(&query, question_end, 0, &records).unwrap();
        assert_eq!(&response[..2], &query[..2]);
        assert_ne!(response[2] & 0x80, 0);
        assert_ne!(response[2] & 0x04, 0);
        assert_ne!(response[3] & 0x80, 0);
        assert_eq!(response[3] & 0x0f, 0);
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 2);
        assert_eq!(&response[12..question_end], &query[12..question_end]);
        let (addresses, _) = parse_response(0, 1, &response).unwrap();
        assert_eq!(addresses.len(), 2);
        let (name, _, _) = parse_question(&response).unwrap();
        assert_eq!(name, "ads.example.com");
    }

    #[test]
    fn predefined_response_preserves_rcode() {
        let query = question("nope.example.com", 1);
        let (_, _, question_end) = parse_question(&query).unwrap();
        let response = predefined_response(&query, question_end, 3, &[]).unwrap();
        assert_eq!(response[3] & 0x0f, 3);
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0);
    }
}

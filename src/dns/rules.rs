use anyhow::{Context, Result, bail};
use std::{collections::HashMap, net::IpAddr};

use super::codec::{normalize, parse_client_subnet, parse_question, validate_strategy};
use crate::routing::CompiledRule;
use crate::singbox::DnsRule;

/// A DNS rule with its hot-path match fields precompiled: regexes are
/// compiled once instead of per query, and domain strings are normalized
/// (lowercased, trailing dot stripped) at build time.
#[derive(Clone)]
pub(crate) struct CompiledDnsRule {
    pub(crate) raw: DnsRule,
    query_type: Vec<u16>,
    domains: Vec<String>,
    suffixes: Vec<String>,
    keywords: Vec<String>,
    regexes: Vec<regex::Regex>,
    logical: Option<(LogicalMode, Vec<CompiledDnsRule>)>,
}

#[derive(Clone, Copy)]
enum LogicalMode {
    And,
    Or,
}

impl CompiledDnsRule {
    pub(crate) fn compile(rule: &DnsRule) -> Result<Self> {
        let query_type = rule
            .query_type
            .iter()
            .map(parse_query_type)
            .collect::<Result<Vec<_>>>()?;
        let domains = rule.domain.iter().map(|v| normalize(v)).collect();
        let suffixes = rule.domain_suffix.iter().map(|v| normalize(v)).collect();
        let keywords = rule
            .domain_keyword
            .iter()
            .map(|v| v.to_ascii_lowercase())
            .collect();
        let regexes = rule
            .domain_regex
            .iter()
            .map(|value| {
                regex::Regex::new(value)
                    .with_context(|| format!("invalid DNS domain_regex: {value}"))
            })
            .collect::<Result<Vec<_>>>()?;
        let logical = if rule.r#type == "logical" {
            let mode = match rule.mode.as_deref().unwrap_or("and") {
                "and" => LogicalMode::And,
                "or" => LogicalMode::Or,
                _ => bail!("unsupported logical DNS mode"),
            };
            Some((
                mode,
                rule.rules
                    .iter()
                    .map(Self::compile)
                    .collect::<Result<Vec<_>>>()?,
            ))
        } else {
            None
        };
        Ok(Self {
            raw: rule.clone(),
            query_type,
            domains,
            suffixes,
            keywords,
            regexes,
            logical,
        })
    }

    fn matches(
        &self,
        name: &str,
        qtype: u16,
        rule_sets: Option<&HashMap<String, Vec<CompiledRule>>>,
    ) -> bool {
        if let Some((mode, rules)) = &self.logical {
            let matched = match mode {
                LogicalMode::And => rules
                    .iter()
                    .all(|rule| rule.matches(name, qtype, rule_sets)),
                LogicalMode::Or => rules
                    .iter()
                    .any(|rule| rule.matches(name, qtype, rule_sets)),
            };
            return if self.raw.invert { !matched } else { matched };
        }
        let query_type = self.query_type.is_empty() || self.query_type.contains(&qtype);
        let exact = self.domains.is_empty() || self.domains.iter().any(|v| v == name);
        let suffix = self.suffixes.is_empty()
            || self
                .suffixes
                .iter()
                .any(|v| name == v || name.strip_suffix(v).is_some_and(|r| r.ends_with('.')));
        let keyword =
            self.keywords.is_empty() || self.keywords.iter().any(|v| name.contains(v.as_str()));
        let regex = self.regexes.is_empty() || self.regexes.iter().any(|v| v.is_match(name));
        let rule_set = self.raw.rule_set.is_empty()
            || rule_sets.is_some_and(|sets| {
                self.raw.rule_set.iter().any(|tag| {
                    sets.get(tag).is_some_and(|rules| {
                        rules.iter().any(|rule| {
                            rule.dns_matches_domain(name) || rule.dns_contains_ip_cidr()
                        })
                    })
                })
            });
        let matched = query_type && exact && suffix && keyword && regex && rule_set;
        if self.raw.invert { !matched } else { matched }
    }
}

pub(crate) fn dns_rule_matches(
    rule: &CompiledDnsRule,
    name: &str,
    qtype: u16,
    rule_sets: Option<&HashMap<String, Vec<CompiledRule>>>,
) -> bool {
    rule.matches(name, qtype, rule_sets)
}

/// The IP CIDR constraints of a rule's rule-sets, used to reject DNS
/// responses whose addresses fall outside them (sing-box `WithAddressLimit`).
pub(crate) fn dns_rule_has_address_limit(
    rule: &CompiledDnsRule,
    rule_sets: Option<&HashMap<String, Vec<CompiledRule>>>,
) -> bool {
    if let Some((_, rules)) = &rule.logical {
        return rules
            .iter()
            .any(|rule| dns_rule_has_address_limit(rule, rule_sets));
    }
    rule_sets.is_some_and(|sets| {
        rule.raw.rule_set.iter().any(|tag| {
            sets.get(tag)
                .is_some_and(|rules| rules.iter().any(|rule| rule.dns_contains_ip_cidr()))
        })
    })
}

/// Post-resolution response check: every address in `addresses` must match
/// the rule's address limits, mirroring sing-box `MatchAddressLimit`.
pub(crate) fn dns_rule_address_limit_matches(
    rule: &CompiledDnsRule,
    name: &str,
    addresses: &[IpAddr],
    rule_sets: Option<&HashMap<String, Vec<CompiledRule>>>,
) -> bool {
    if let Some((mode, rules)) = &rule.logical {
        let matched = match mode {
            LogicalMode::And => rules
                .iter()
                .all(|rule| dns_rule_address_limit_matches(rule, name, addresses, rule_sets)),
            LogicalMode::Or => rules
                .iter()
                .any(|rule| dns_rule_address_limit_matches(rule, name, addresses, rule_sets)),
        };
        return if rule.raw.invert { !matched } else { matched };
    }
    let sets_matched = rule_sets.is_none_or(|sets| {
        rule.raw.rule_set.iter().any(|tag| {
            sets.get(tag).is_some_and(|rules| {
                rules.iter().any(|rule| {
                    addresses
                        .iter()
                        .any(|address| rule.dns_matches_address(*address, Some(name)))
                })
            })
        })
    });
    if rule.raw.invert {
        !sets_matched
    } else {
        sets_matched
    }
}

pub(crate) fn validate_dns_rule(rule: &DnsRule, top_level: bool) -> Result<()> {
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
        for record in rule.answer.iter().chain(&rule.ns).chain(&rule.extra) {
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

pub(crate) fn parse_query_type(value: &serde_json::Value) -> Result<u16> {
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

pub(crate) fn parse_rcode(value: Option<&serde_json::Value>) -> Result<u8> {
    let Some(value) = value else {
        return Ok(0);
    };
    if let Some(number) = value.as_u64() {
        return u8::try_from(number).context("DNS rcode exceeds 255");
    }
    let value = value
        .as_str()
        .context("DNS rcode must be a number or string")?;
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

/// One parsed resource record from a `predefined` DNS rule answer/ns/extra
/// entry, encoded ready for insertion into a response.
#[derive(Debug, Clone)]
pub(crate) struct PredefinedRecord {
    pub(crate) owner: String,
    pub(crate) ttl: u32,
    pub(crate) kind: u16,
    pub(crate) rdata: Vec<u8>,
}

/// Parse a text resource record such as `. 2147483647 IN A 0.0.0.0` or
/// `localhost. IN TXT "Hello"` into an encoded record. The owner name is
/// kept verbatim; `*`-prefixed owners are resolved against the query name
/// when the response is built, matching sing-box behavior.
pub(crate) fn parse_dns_record(record: &str) -> Result<PredefinedRecord> {
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
            Err(_)
                if matches!(
                    first,
                    "IN" | "CH"
                        | "HS"
                        | "A"
                        | "AAAA"
                        | "CNAME"
                        | "NS"
                        | "PTR"
                        | "MX"
                        | "SOA"
                        | "TXT"
                        | "SRV"
                        | "CAA"
                ) =>
            {
                (3600, Box::new(std::iter::once(first).chain(iter)))
            }
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
            data.extend(encode_name(
                tokens.next().context("MX record is missing an exchange")?,
            )?);
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
            data.extend(encode_name(
                tokens.next().context("SRV record is missing a target")?,
            )?);
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
pub(crate) fn predefined_response(
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::singbox::RouteRule;
    use std::collections::HashMap;
    use std::sync::{Arc, RwLock};

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
    fn dns_rule_matches_query_type_regex_and_invert() {
        let rule = DnsRule {
            query_type: vec![serde_json::Value::String("HTTPS".into())],
            domain_regex: vec![r"^api\d+\.example$".into()],
            ..Default::default()
        };
        let compiled = CompiledDnsRule::compile(&rule).unwrap();
        assert!(dns_rule_matches(&compiled, "api12.example", 65, None));
        assert!(!dns_rule_matches(&compiled, "api12.example", 1, None));
        assert!(!dns_rule_matches(&compiled, "www.example", 65, None));
        assert!(dns_rule_matches(
            &CompiledDnsRule::compile(&DnsRule {
                invert: true,
                ..rule
            })
            .unwrap(),
            "www.example",
            65,
            None
        ));
    }

    #[test]
    fn rule_suffix() {
        let r = CompiledDnsRule::compile(&DnsRule {
            domain_suffix: vec!["example.com".into()],
            ..Default::default()
        })
        .unwrap();
        assert!(dns_rule_matches(&r, "www.example.com", 1, None));
        assert!(!dns_rule_matches(&r, "badexample.com", 1, None));
    }

    #[test]
    fn dns_rule_matches_rule_set_tags() {
        let set = vec![
            CompiledRule::compile(
                &RouteRule {
                    domain_suffix: vec!["example.com".into()],
                    ..Default::default()
                },
                &HashMap::new(),
                false,
            )
            .unwrap(),
        ];
        let mut sets = HashMap::new();
        sets.insert("geosite-cn".into(), set);
        let rule_sets = Arc::new(RwLock::new(sets));

        let rule = CompiledDnsRule::compile(&DnsRule {
            rule_set: vec!["geosite-cn".into()],
            server: Some("dns_local".into()),
            ..Default::default()
        })
        .unwrap();
        let unlocked = rule_sets.read().unwrap();
        assert!(dns_rule_matches(
            &rule,
            "www.example.com",
            1,
            Some(&unlocked)
        ));
        assert!(!dns_rule_matches(
            &rule,
            "www.elsewhere.net",
            1,
            Some(&unlocked)
        ));
        assert!(!dns_rule_matches(&rule, "www.example.com", 1, None));
    }

    #[test]
    fn parse_query_type_accepts_numbers_and_names() {
        assert_eq!(parse_query_type(&serde_json::json!(1)).unwrap(), 1);
        assert_eq!(parse_query_type(&serde_json::json!("AAAA")).unwrap(), 28);
        assert_eq!(parse_query_type(&serde_json::json!("HTTPS")).unwrap(), 65);
        assert!(
            parse_query_type(&serde_json::json!(70000))
                .unwrap_err()
                .to_string()
                .contains("65535")
        );
        assert!(parse_query_type(&serde_json::json!("BOGUS")).is_err());
    }

    #[test]
    fn parse_rcode_accepts_names_and_numbers() {
        assert_eq!(parse_rcode(None).unwrap(), 0);
        assert_eq!(parse_rcode(Some(&serde_json::json!("NOERROR"))).unwrap(), 0);
        assert_eq!(
            parse_rcode(Some(&serde_json::json!("NXDOMAIN"))).unwrap(),
            3
        );
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
        let (addresses, _) = crate::dns::codec::parse_response(0, 1, &response).unwrap();
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

    #[test]
    fn validate_dns_rule_accepts_valid_rules_and_rejects_unknown_types() {
        assert!(validate_dns_rule(&DnsRule::default(), true).is_ok());
        assert!(
            validate_dns_rule(
                &DnsRule {
                    r#type: "bogus".into(),
                    ..Default::default()
                },
                true
            )
            .is_err()
        );
        assert!(
            validate_dns_rule(
                &DnsRule {
                    r#type: "logical".into(),
                    mode: Some("or".into()),
                    rules: vec![DnsRule::default()],
                    ..Default::default()
                },
                true
            )
            .is_ok()
        );
    }
}

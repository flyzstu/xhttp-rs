use std::{
    collections::HashMap,
    net::IpAddr,
    ops::RangeInclusive,
    sync::{Arc, RwLock},
};

use anyhow::{Context, Result, bail};
use ipnet::IpNet;

use crate::linux_route::LinuxMetadataScope;
use crate::singbox::{RouteConfig, RouteRule};

#[derive(Debug, Clone, Default)]
pub struct RouteContext<'a> {
    pub domain: Option<&'a str>,
    pub destination_ip: Option<IpAddr>,
    pub destination_port: Option<u16>,
    pub source_ip: Option<IpAddr>,
    pub source_port: Option<u16>,
    pub network: Option<&'a str>,
    pub protocol: Option<&'a str>,
    pub client: Option<&'a str>,
    pub inbound: Option<&'a str>,
    pub auth_user: Option<&'a str>,
    pub process_name: Option<&'a str>,
    pub process_path: Option<&'a str>,
    pub package_name: Option<&'a str>,
    pub user: Option<&'a str>,
    pub user_id: Option<u32>,
    pub clash_mode: Option<&'a str>,
    pub network_type: Option<&'a str>,
    pub network_is_expensive: bool,
    pub network_is_constrained: bool,
    pub wifi_ssid: Option<&'a str>,
    pub wifi_bssid: Option<&'a str>,
    pub interface_addresses: Option<&'a HashMap<String, Vec<IpAddr>>>,
    pub network_interface_addresses: Option<&'a HashMap<String, Vec<IpAddr>>>,
    pub source_mac_address: Option<&'a str>,
    pub source_hostname: Option<&'a str>,
    pub default_interface_addresses: &'a [IpAddr],
    pub preferred_by: &'a [String],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteDecision {
    Outbound(String),
    Reject,
    HijackDns,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RouteOptions {
    pub override_address: Option<String>,
    pub override_port: Option<u16>,
    pub network_strategy: Option<String>,
    pub fallback_delay: Option<String>,
    pub udp_disable_domain_unmapping: bool,
    pub udp_connect: bool,
    pub udp_timeout: Option<String>,
    pub tls_fragment: bool,
    pub tls_fragment_fallback_delay: Option<String>,
    pub tls_record_fragment: bool,
    pub tls_spoof: Option<String>,
    pub tls_spoof_method: Option<String>,
    pub bind_interface: Option<String>,
    pub inet4_bind_address: Option<String>,
    pub inet6_bind_address: Option<String>,
    pub routing_mark: Option<u32>,
    pub reuse_addr: bool,
    pub connect_timeout: Option<String>,
    pub tcp_fast_open: bool,
    pub tcp_multi_path: bool,
    pub udp_fragment: Option<bool>,
    pub domain_strategy: Option<String>,
    pub reject_method: Option<String>,
    pub reject_no_drop: bool,
}

impl RouteOptions {
    pub fn merge(&mut self, newer: &Self) {
        if newer.override_address.is_some() {
            self.override_address = newer.override_address.clone();
        }
        if newer.override_port.is_some() {
            self.override_port = newer.override_port;
        }
        if newer.network_strategy.is_some() {
            self.network_strategy = newer.network_strategy.clone();
        }
        if newer.fallback_delay.is_some() {
            self.fallback_delay = newer.fallback_delay.clone();
        }
        self.udp_disable_domain_unmapping |= newer.udp_disable_domain_unmapping;
        self.udp_connect |= newer.udp_connect;
        if newer.udp_timeout.is_some() {
            self.udp_timeout = newer.udp_timeout.clone();
        }
        self.tls_fragment |= newer.tls_fragment;
        if newer.tls_fragment_fallback_delay.is_some() {
            self.tls_fragment_fallback_delay = newer.tls_fragment_fallback_delay.clone();
        }
        self.tls_record_fragment |= newer.tls_record_fragment;
        if newer.tls_spoof.is_some() {
            self.tls_spoof = newer.tls_spoof.clone();
        }
        if newer.tls_spoof_method.is_some() {
            self.tls_spoof_method = newer.tls_spoof_method.clone();
        }
        if newer.bind_interface.is_some() {
            self.bind_interface = newer.bind_interface.clone();
        }
        if newer.inet4_bind_address.is_some() {
            self.inet4_bind_address = newer.inet4_bind_address.clone();
        }
        if newer.inet6_bind_address.is_some() {
            self.inet6_bind_address = newer.inet6_bind_address.clone();
        }
        if newer.routing_mark.is_some() {
            self.routing_mark = newer.routing_mark;
        }
        self.reuse_addr |= newer.reuse_addr;
        if newer.connect_timeout.is_some() {
            self.connect_timeout = newer.connect_timeout.clone();
        }
        self.tcp_fast_open |= newer.tcp_fast_open;
        self.tcp_multi_path |= newer.tcp_multi_path;
        if newer.udp_fragment.is_some() {
            self.udp_fragment = newer.udp_fragment;
        }
        if newer.domain_strategy.is_some() {
            self.domain_strategy = newer.domain_strategy.clone();
        }
        if newer.reject_method.is_some() {
            self.reject_method = newer.reject_method.clone();
        }
        self.reject_no_drop |= newer.reject_no_drop;
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleAction {
    Route {
        decision: RouteDecision,
        options: RouteOptions,
    },
    RouteOptions(RouteOptions),
    Sniff {
        sniffers: Vec<String>,
        timeout: Option<String>,
    },
    Resolve {
        server: Option<String>,
        timeout: Option<String>,
        strategy: Option<String>,
        disable_cache: bool,
        rewrite_ttl: Option<u32>,
        client_subnet: Option<String>,
    },
}

#[derive(Debug, Clone)]
pub struct Router {
    rules: Arc<RwLock<Vec<CompiledRule>>>,
    rule_sets: Arc<RwLock<HashMap<String, Vec<CompiledRule>>>>,
    final_outbound: String,
    default_options: Arc<RwLock<RouteOptions>>,
}

#[derive(Debug, Clone)]
struct CompiledRule {
    logical_mode: Option<LogicalMode>,
    logical_rules: Vec<CompiledRule>,
    domains: Vec<String>,
    suffixes: Vec<String>,
    keywords: Vec<String>,
    regexes: Vec<regex::Regex>,
    cidrs: Vec<IpNet>,
    source_cidrs: Vec<IpNet>,
    ip_versions: Vec<u8>,
    ip_private: bool,
    source_private: bool,
    source_ports: Vec<RangeInclusive<u16>>,
    ports: Vec<RangeInclusive<u16>>,
    networks: Vec<String>,
    protocols: Vec<String>,
    clients: Vec<String>,
    inbounds: Vec<String>,
    auth_users: Vec<String>,
    process_names: Vec<String>,
    process_paths: Vec<String>,
    process_path_regexes: Vec<regex::Regex>,
    package_names: Vec<String>,
    package_name_regexes: Vec<regex::Regex>,
    users: Vec<String>,
    user_ids: Vec<u32>,
    clash_mode: Option<String>,
    network_types: Vec<String>,
    network_is_expensive: bool,
    network_is_constrained: bool,
    wifi_ssids: Vec<String>,
    wifi_bssids: Vec<String>,
    interface_addresses: HashMap<String, Vec<IpNet>>,
    network_interface_addresses: HashMap<String, Vec<IpNet>>,
    source_mac_addresses: Vec<String>,
    source_hostnames: Vec<String>,
    default_interface_addresses: Vec<IpNet>,
    preferred_by: Vec<String>,
    rule_sets: Vec<Vec<CompiledRule>>,
    rule_set_ip_cidr_match_source: bool,
    action: RuleAction,
    invert: bool,
}

#[derive(Debug, Clone, Copy)]
enum LogicalMode {
    And,
    Or,
}

impl Router {
    pub fn compile(config: &RouteConfig, default_outbound: impl Into<String>) -> Result<Self> {
        Self::compile_inner(config, default_outbound.into(), false)
    }

    pub fn compile_runtime(
        config: &RouteConfig,
        default_outbound: impl Into<String>,
    ) -> Result<Self> {
        Self::compile_inner(config, default_outbound.into(), true)
    }

    fn compile_inner(
        config: &RouteConfig,
        default_outbound: String,
        fetch_remote: bool,
    ) -> Result<Self> {
        let final_outbound = config.final_outbound.clone().unwrap_or(default_outbound);
        let rule_sets = load_rule_sets(config, fetch_remote)?;
        let rules = config
            .rules
            .iter()
            .map(|rule| CompiledRule::compile(rule, &rule_sets, true))
            .collect::<Result<_>>()?;
        Ok(Self {
            rules: Arc::new(RwLock::new(rules)),
            rule_sets: Arc::new(RwLock::new(rule_sets)),
            final_outbound,
            default_options: Arc::new(RwLock::new(RouteOptions {
                bind_interface: config.default_interface.clone(),
                routing_mark: config.default_mark,
                network_strategy: config.default_network_strategy.clone(),
                fallback_delay: config.default_fallback_delay.clone(),
                ..Default::default()
            })),
        })
    }

    pub fn route(&self, context: &RouteContext<'_>) -> RouteDecision {
        self.rules
            .read()
            .expect("route rule lock poisoned")
            .iter()
            .filter(|rule| rule.matches(context))
            .find_map(|rule| match &rule.action {
                RuleAction::Route { decision, .. } => Some(decision.clone()),
                _ => None,
            })
            .unwrap_or_else(|| RouteDecision::Outbound(self.final_outbound.clone()))
    }

    pub fn next_action(
        &self,
        context: &RouteContext<'_>,
        from: usize,
    ) -> Option<(usize, RuleAction)> {
        self.rules
            .read()
            .expect("route rule lock poisoned")
            .iter()
            .enumerate()
            .skip(from)
            .find(|(_, rule)| rule.matches(context))
            .map(|(index, rule)| (index, rule.action.clone()))
    }

    pub fn final_outbound(&self) -> &str {
        &self.final_outbound
    }

    pub fn default_options(&self) -> RouteOptions {
        self.default_options
            .read()
            .expect("route default options lock poisoned")
            .clone()
    }

    pub fn replace_from(&self, updated: Self) {
        let rules = updated
            .rules
            .read()
            .expect("updated route rule lock poisoned")
            .clone();
        *self.rules.write().expect("route rule lock poisoned") = rules;
        *self
            .rule_sets
            .write()
            .expect("route rule-set lock poisoned") = updated
            .rule_sets
            .read()
            .expect("updated route rule-set lock poisoned")
            .clone();
        *self
            .default_options
            .write()
            .expect("route default options lock poisoned") = updated
            .default_options
            .read()
            .expect("updated route default options lock poisoned")
            .clone();
    }

    pub(crate) fn rule_set_ip_cidrs(&self, tags: &[String]) -> Result<Vec<IpNet>> {
        let sets = self.rule_sets.read().expect("route rule-set lock poisoned");
        extract_rule_set_ip_cidrs(&sets, tags)
    }
}

impl CompiledRule {
    fn metadata_scope(&self) -> LinuxMetadataScope {
        let mut scope = LinuxMetadataScope {
            process: !self.process_names.is_empty()
                || !self.process_paths.is_empty()
                || !self.process_path_regexes.is_empty()
                || !self.package_names.is_empty()
                || !self.package_name_regexes.is_empty(),
            user: !self.users.is_empty() || !self.user_ids.is_empty(),
            interface: !self.interface_addresses.is_empty()
                || !self.network_interface_addresses.is_empty(),
            network: !self.network_types.is_empty()
                || self.network_is_expensive
                || self.network_is_constrained
                || !self.wifi_ssids.is_empty()
                || !self.wifi_bssids.is_empty()
                || !self.default_interface_addresses.is_empty(),
            mac: !self.source_mac_addresses.is_empty(),
            hostname: !self.source_hostnames.is_empty(),
        };
        for nested in &self.logical_rules {
            scope = scope.union(nested.metadata_scope());
        }
        for set in &self.rule_sets {
            for rule in set {
                scope = scope.union(rule.metadata_scope());
            }
        }
        scope
    }
}

impl Router {
    pub(crate) fn linux_metadata_scope(&self) -> LinuxMetadataScope {
        self.rules
            .read()
            .expect("route rule lock poisoned")
            .iter()
            .fold(LinuxMetadataScope::default(), |scope, rule| {
                scope.union(rule.metadata_scope())
            })
    }
}

impl CompiledRule {
    fn compile(
        rule: &RouteRule,
        available_sets: &HashMap<String, Vec<CompiledRule>>,
        require_decision: bool,
    ) -> Result<Self> {
        if !rule.geosite.is_empty() || !rule.geoip.is_empty() || !rule.source_geoip.is_empty() {
            bail!(
                "legacy geosite/geoip fields require external databases; use source or SRS rule-sets"
            )
        }
        if !rule.preferred_by.is_empty() {
            bail!("preferred_by requires an outbound with preferred-route support")
        }
        let logical_mode = if rule.r#type == "logical" {
            Some(match rule.mode.as_deref().unwrap_or("and") {
                "and" => LogicalMode::And,
                "or" => LogicalMode::Or,
                value => bail!("unsupported logical route mode: {value}"),
            })
        } else {
            if !matches!(rule.r#type.as_str(), "" | "default") {
                bail!("unsupported route rule type: {}", rule.r#type)
            }
            None
        };
        if logical_mode.is_some() && rule.rules.is_empty() {
            bail!("logical route rule requires nested rules")
        }
        let action = if require_decision {
            match rule.action.as_deref() {
                Some("reject") => RuleAction::Route {
                    decision: RouteDecision::Reject,
                    options: route_options(rule)?,
                },
                Some("hijack-dns") => RuleAction::Route {
                    decision: RouteDecision::HijackDns,
                    options: RouteOptions::default(),
                },
                Some("direct") => RuleAction::Route {
                    decision: RouteDecision::Outbound("direct".into()),
                    options: route_options(rule)?,
                },
                Some("bypass") => RuleAction::Route {
                    decision: RouteDecision::Outbound(
                        rule.outbound.clone().unwrap_or_else(|| "direct".into()),
                    ),
                    options: route_options(rule)?,
                },
                Some("route") | None => RuleAction::Route {
                    decision: RouteDecision::Outbound(
                        rule.outbound
                            .clone()
                            .context("route rule requires outbound")?,
                    ),
                    options: route_options(rule)?,
                },
                Some("route-options") => RuleAction::RouteOptions(route_options(rule)?),
                Some("sniff") => RuleAction::Sniff {
                    sniffers: lower(&rule.sniffer),
                    timeout: rule.timeout.clone(),
                },
                Some("resolve") => {
                    RuleAction::Resolve {
                        server: rule.server.clone(),
                        timeout: rule.timeout.clone(),
                        strategy: rule.strategy.clone(),
                        // This resolver never serves optimistic/stale entries, so
                        // disable_optimistic_cache is inherently satisfied.
                        disable_cache: rule.disable_cache,
                        rewrite_ttl: rule.rewrite_ttl,
                        client_subnet: rule.client_subnet.clone(),
                    }
                }
                Some(value) => bail!("unsupported route action: {value}"),
            }
        } else {
            RuleAction::Route {
                decision: RouteDecision::Reject,
                options: RouteOptions::default(),
            }
        };
        let rule_sets = rule
            .rule_set
            .iter()
            .map(|tag| {
                available_sets
                    .get(tag)
                    .cloned()
                    .with_context(|| format!("unknown route rule-set: {tag}"))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            logical_mode,
            logical_rules: rule
                .rules
                .iter()
                .map(|nested| Self::compile(nested, available_sets, false))
                .collect::<Result<_>>()?,
            domains: rule.domain.iter().map(|v| normalize_domain(v)).collect(),
            suffixes: rule
                .domain_suffix
                .iter()
                .map(|v| normalize_domain(v))
                .collect(),
            keywords: lower(&rule.domain_keyword),
            regexes: rule
                .domain_regex
                .iter()
                .map(|value| {
                    regex::Regex::new(value)
                        .with_context(|| format!("invalid domain regex {value}"))
                })
                .collect::<Result<_>>()?,
            cidrs: parse_nets(&rule.ip_cidr)?,
            source_cidrs: parse_nets(&rule.source_ip_cidr)?,
            ip_versions: rule.ip_version.clone(),
            ip_private: rule.ip_is_private,
            source_private: rule.source_ip_is_private,
            source_ports: rule
                .source_port
                .iter()
                .map(|value| *value..=*value)
                .chain(parse_ports(&rule.source_port_range)?)
                .collect(),
            ports: rule
                .port
                .iter()
                .map(|v| *v..=*v)
                .chain(parse_ports(&rule.port_range)?)
                .collect(),
            networks: lower(&rule.network),
            protocols: lower(&rule.protocol),
            clients: lower(&rule.client),
            inbounds: rule.inbound.clone(),
            auth_users: rule.auth_user.clone(),
            process_names: lower(&rule.process_name),
            process_paths: rule.process_path.clone(),
            process_path_regexes: compile_regexes(&rule.process_path_regex, "process path")?,
            package_names: lower(&rule.package_name),
            package_name_regexes: compile_regexes(&rule.package_name_regex, "package name")?,
            users: rule.user.clone(),
            user_ids: rule.user_id.clone(),
            clash_mode: rule
                .clash_mode
                .as_ref()
                .map(|value| value.to_ascii_lowercase()),
            network_types: lower(&rule.network_type),
            network_is_expensive: rule.network_is_expensive,
            network_is_constrained: rule.network_is_constrained,
            wifi_ssids: rule.wifi_ssid.clone(),
            wifi_bssids: lower(&rule.wifi_bssid),
            interface_addresses: compile_address_map(&rule.interface_address, "interface_address")?,
            network_interface_addresses: compile_address_map(
                &rule.network_interface_address,
                "network_interface_address",
            )?,
            source_mac_addresses: lower(&rule.source_mac_address),
            source_hostnames: lower(&rule.source_hostname),
            default_interface_addresses: parse_nets(&rule.default_interface_address)?,
            preferred_by: rule.preferred_by.clone(),
            rule_sets,
            rule_set_ip_cidr_match_source: rule.rule_set_ip_cidr_match_source,
            action,
            invert: rule.invert,
        })
    }
    fn matches(&self, c: &RouteContext<'_>) -> bool {
        if let Some(mode) = self.logical_mode {
            let matched = match mode {
                LogicalMode::And => self.logical_rules.iter().all(|rule| rule.matches(c)),
                LogicalMode::Or => self.logical_rules.iter().any(|rule| rule.matches(c)),
            };
            return if self.invert { !matched } else { matched };
        }
        let domain = c.domain.map(normalize_domain);
        let matched = (self.domains.is_empty()
            || domain.as_ref().is_some_and(|d| self.domains.contains(d)))
            && (self.suffixes.is_empty()
                || domain.as_ref().is_some_and(|d| {
                    self.suffixes
                        .iter()
                        .any(|s| d == s || d.ends_with(&format!(".{s}")))
                }))
            && (self.keywords.is_empty()
                || domain
                    .as_ref()
                    .is_some_and(|d| self.keywords.iter().any(|value| d.contains(value))))
            && (self.regexes.is_empty()
                || domain
                    .as_ref()
                    .is_some_and(|d| self.regexes.iter().any(|value| value.is_match(d))))
            && (self.cidrs.is_empty()
                || c.destination_ip
                    .is_some_and(|ip| self.cidrs.iter().any(|n| n.contains(&ip))))
            && (self.source_cidrs.is_empty()
                || c.source_ip
                    .is_some_and(|ip| self.source_cidrs.iter().any(|n| n.contains(&ip))))
            && (self.ip_versions.is_empty()
                || c.destination_ip.is_some_and(|ip| {
                    self.ip_versions.iter().any(|version| {
                        matches!((version, ip), (4, IpAddr::V4(_)) | (6, IpAddr::V6(_)))
                    })
                }))
            && (!self.ip_private || c.destination_ip.is_some_and(is_private))
            && (!self.source_private || c.source_ip.is_some_and(is_private))
            && (self.source_ports.is_empty()
                || c.source_port.is_some_and(|port| {
                    self.source_ports.iter().any(|range| range.contains(&port))
                }))
            && (self.ports.is_empty()
                || c.destination_port
                    .is_some_and(|p| self.ports.iter().any(|r| r.contains(&p))))
            && match_field(&self.networks, c.network)
            && match_field(&self.protocols, c.protocol)
            && match_field(&self.clients, c.client)
            && (self.inbounds.is_empty()
                || c.inbound
                    .is_some_and(|v| self.inbounds.iter().any(|x| x == v)))
            && match_field(&self.auth_users, c.auth_user)
            && match_field(&self.process_names, c.process_name)
            && (self.process_paths.is_empty()
                || c.process_path
                    .is_some_and(|value| self.process_paths.iter().any(|item| item == value)))
            && (self.process_path_regexes.is_empty()
                || c.process_path.is_some_and(|value| {
                    self.process_path_regexes
                        .iter()
                        .any(|regex| regex.is_match(value))
                }))
            && match_field(&self.package_names, c.package_name)
            && (self.package_name_regexes.is_empty()
                || c.package_name.is_some_and(|value| {
                    self.package_name_regexes
                        .iter()
                        .any(|regex| regex.is_match(value))
                }))
            && match_field(&self.users, c.user)
            && (self.user_ids.is_empty()
                || c.user_id
                    .is_some_and(|value| self.user_ids.contains(&value)))
            && (self.clash_mode.is_none()
                || self
                    .clash_mode
                    .as_deref()
                    .zip(c.clash_mode)
                    .is_some_and(|(expected, actual)| expected.eq_ignore_ascii_case(actual)))
            && match_field(&self.network_types, c.network_type)
            && (!self.network_is_expensive || c.network_is_expensive)
            && (!self.network_is_constrained || c.network_is_constrained)
            && match_field(&self.wifi_ssids, c.wifi_ssid)
            && match_field(&self.wifi_bssids, c.wifi_bssid)
            && address_map_matches(&self.interface_addresses, c.interface_addresses)
            && address_map_matches(
                &self.network_interface_addresses,
                c.network_interface_addresses,
            )
            && match_field(&self.source_mac_addresses, c.source_mac_address)
            && match_field(&self.source_hostnames, c.source_hostname)
            && (self.default_interface_addresses.is_empty()
                || c.default_interface_addresses.iter().any(|address| {
                    self.default_interface_addresses
                        .iter()
                        .any(|network| network.contains(address))
                }))
            && (self.preferred_by.is_empty()
                || c.preferred_by
                    .iter()
                    .any(|tag| self.preferred_by.contains(tag)))
            && (self.rule_sets.is_empty() || {
                let mut source_context = c.clone();
                if self.rule_set_ip_cidr_match_source {
                    source_context.destination_ip = c.source_ip;
                }
                self.rule_sets.iter().flatten().any(|rule| {
                    rule.matches(if self.rule_set_ip_cidr_match_source {
                        &source_context
                    } else {
                        c
                    })
                })
            });
        if self.invert { !matched } else { matched }
    }
}

#[derive(serde::Deserialize)]
struct SourceRuleSet {
    rules: Vec<RouteRule>,
}

fn load_rule_sets(
    config: &RouteConfig,
    fetch_remote: bool,
) -> Result<HashMap<String, Vec<CompiledRule>>> {
    let mut result = HashMap::new();
    for set in &config.rule_set {
        if set.tag.is_empty() {
            bail!("route rule-set tag must not be empty")
        }
        let rules = match set.r#type.as_str() {
            "inline" => set.rules.clone(),
            "local" | "" => {
                let path = set
                    .path
                    .as_deref()
                    .with_context(|| format!("local rule-set {} requires path", set.tag))?;
                let data =
                    std::fs::read(path).with_context(|| format!("read route rule-set {path}"))?;
                decode_rule_set(&data, rule_set_format(set, path)?)
                    .with_context(|| format!("parse route rule-set {path}"))?
            }
            "remote" => {
                if !fetch_remote {
                    Vec::new()
                } else {
                    load_remote_rule_set(set)?
                }
            }
            value => bail!("unsupported route rule-set type: {value}"),
        };
        let compiled = rules
            .iter()
            .map(|rule| CompiledRule::compile(rule, &HashMap::new(), false))
            .collect::<Result<Vec<_>>>()?;
        if result.insert(set.tag.clone(), compiled).is_some() {
            bail!("duplicate route rule-set tag: {}", set.tag)
        }
    }
    Ok(result)
}

pub(crate) fn load_rule_set_ip_cidrs(config: &RouteConfig, tags: &[String]) -> Result<Vec<IpNet>> {
    let sets = load_rule_sets(config, true)?;
    extract_rule_set_ip_cidrs(&sets, tags)
}

fn extract_rule_set_ip_cidrs(
    sets: &HashMap<String, Vec<CompiledRule>>,
    tags: &[String],
) -> Result<Vec<IpNet>> {
    let mut cidrs = Vec::new();
    for tag in tags {
        let rules = sets
            .get(tag)
            .with_context(|| format!("TUN route rule-set not found: {tag}"))?;
        for rule in rules {
            collect_destination_cidrs(rule, &mut cidrs);
        }
    }
    cidrs.sort_by_key(ToString::to_string);
    cidrs.dedup();
    Ok(cidrs)
}

fn collect_destination_cidrs(rule: &CompiledRule, cidrs: &mut Vec<IpNet>) {
    if !rule.invert {
        cidrs.extend(rule.cidrs.iter().copied());
    }
    for nested in &rule.logical_rules {
        collect_destination_cidrs(nested, cidrs);
    }
}

fn load_remote_rule_set(set: &crate::singbox::RuleSetConfig) -> Result<Vec<RouteRule>> {
    use std::{
        collections::hash_map::DefaultHasher,
        hash::{Hash, Hasher},
        path::PathBuf,
    };
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
    let format = rule_set_format(set, url)?;
    let mut hasher = DefaultHasher::new();
    url.hash(&mut hasher);
    let cache_root = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("xhttp-cache"));
    let cache_path = cache_root.join("rule-set").join(format!(
        "{:016x}.{}",
        hasher.finish(),
        if format == "binary" { "srs" } else { "json" }
    ));
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
            if let Some(parent) = cache_path.parent() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("create rule-set cache {}", parent.display()))?;
            }
            std::fs::write(&cache_path, &data)
                .with_context(|| format!("write rule-set cache {}", cache_path.display()))?;
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

fn rule_set_format<'a>(set: &'a crate::singbox::RuleSetConfig, location: &str) -> Result<&'a str> {
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

fn decode_rule_set(data: &[u8], format: &str) -> Result<Vec<RouteRule>> {
    match format {
        "source" => Ok(serde_json::from_slice::<SourceRuleSet>(data)?.rules),
        "binary" => crate::srs::decode(data),
        _ => unreachable!("rule-set format was validated"),
    }
}

fn normalize_domain(value: &str) -> String {
    value.trim_end_matches('.').to_ascii_lowercase()
}
fn lower(values: &[String]) -> Vec<String> {
    values.iter().map(|v| v.to_ascii_lowercase()).collect()
}
fn compile_regexes(values: &[String], field: &str) -> Result<Vec<regex::Regex>> {
    values
        .iter()
        .map(|value| {
            regex::Regex::new(value)
                .with_context(|| format!("invalid {field} regular expression {value}"))
        })
        .collect()
}
fn compile_address_map(
    values: &HashMap<String, Vec<String>>,
    field: &str,
) -> Result<HashMap<String, Vec<IpNet>>> {
    values
        .iter()
        .map(|(key, values)| {
            Ok((
                key.to_ascii_lowercase(),
                values
                    .iter()
                    .map(|value| {
                        value
                            .parse()
                            .with_context(|| format!("invalid {field} prefix {value}"))
                    })
                    .collect::<Result<Vec<_>>>()?,
            ))
        })
        .collect()
}
fn address_map_matches(
    expected: &HashMap<String, Vec<IpNet>>,
    actual: Option<&HashMap<String, Vec<IpAddr>>>,
) -> bool {
    expected.is_empty()
        || actual.is_some_and(|actual| {
            expected.iter().any(|(key, networks)| {
                actual.get(key).is_some_and(|addresses| {
                    addresses
                        .iter()
                        .any(|ip| networks.iter().any(|network| network.contains(ip)))
                })
            })
        })
}
fn route_options(rule: &RouteRule) -> Result<RouteOptions> {
    if rule.tls_fragment && rule.tls_record_fragment {
        bail!("tls_fragment and tls_record_fragment are mutually exclusive")
    }
    #[cfg(target_os = "linux")]
    if rule.tls_spoof.is_some() {
        bail!("tls_spoof is not supported by sing-box or xhttp-rs on Linux")
    }
    #[cfg(target_os = "linux")]
    if rule.tcp_multi_path {
        bail!("tcp_multi_path is not available on Linux")
    }
    if rule.action.as_deref() == Some("reject")
        && !matches!(
            rule.method.as_deref(),
            None | Some("") | Some("drop") | Some("reply")
        )
    {
        bail!(
            "unsupported reject method: {}",
            rule.method.as_deref().unwrap()
        )
    }
    Ok(RouteOptions {
        override_address: rule.override_address.clone(),
        override_port: rule.override_port,
        network_strategy: rule.network_strategy.clone(),
        fallback_delay: rule.fallback_delay.clone(),
        udp_disable_domain_unmapping: rule.udp_disable_domain_unmapping,
        udp_connect: rule.udp_connect,
        udp_timeout: rule.udp_timeout.clone(),
        tls_fragment: rule.tls_fragment,
        tls_fragment_fallback_delay: rule.tls_fragment_fallback_delay.clone(),
        tls_record_fragment: rule.tls_record_fragment,
        tls_spoof: rule.tls_spoof.clone(),
        tls_spoof_method: rule.tls_spoof_method.clone(),
        bind_interface: rule.bind_interface.clone(),
        inet4_bind_address: rule.inet4_bind_address.clone(),
        inet6_bind_address: rule.inet6_bind_address.clone(),
        routing_mark: rule.routing_mark,
        reuse_addr: rule.reuse_addr,
        connect_timeout: rule.connect_timeout.clone(),
        tcp_fast_open: rule.tcp_fast_open,
        tcp_multi_path: rule.tcp_multi_path,
        udp_fragment: rule.udp_fragment,
        domain_strategy: rule.domain_strategy.clone(),
        reject_method: rule.method.clone(),
        reject_no_drop: rule.no_drop,
    })
}
fn match_field(expected: &[String], actual: Option<&str>) -> bool {
    expected.is_empty()
        || actual.is_some_and(|v| expected.iter().any(|x| x.eq_ignore_ascii_case(v)))
}
fn parse_nets(values: &[String]) -> Result<Vec<IpNet>> {
    values
        .iter()
        .map(|v| v.parse().with_context(|| format!("invalid CIDR {v}")))
        .collect()
}
fn parse_ports(values: &[String]) -> Result<Vec<RangeInclusive<u16>>> {
    values
        .iter()
        .map(|v| {
            let (a, b) = v.split_once(':').unwrap_or((v, v));
            Ok(a.parse()?..=b.parse()?)
        })
        .collect()
}
fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(value) => {
            value.is_private()
                || value.is_loopback()
                || value.is_link_local()
                || value.is_unspecified()
        }
        IpAddr::V6(value) => {
            value.is_loopback()
                || value.is_unspecified()
                || (value.segments()[0] & 0xfe00) == 0xfc00
                || (value.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::singbox::RuleSetConfig;
    #[test]
    fn first_matching_rule_wins() {
        let c = RouteConfig {
            rules: vec![RouteRule {
                domain_suffix: vec!["example.com".into()],
                outbound: Some("proxy".into()),
                ..Default::default()
            }],
            final_outbound: Some("direct".into()),
            ..Default::default()
        };
        let r = Router::compile(&c, "direct").unwrap();
        assert_eq!(
            r.route(&RouteContext {
                domain: Some("WWW.Example.Com."),
                ..Default::default()
            }),
            RouteDecision::Outbound("proxy".into())
        );
        assert_eq!(
            r.route(&RouteContext {
                domain: Some("example.net"),
                ..Default::default()
            }),
            RouteDecision::Outbound("direct".into())
        );
    }
    #[test]
    fn regex_private_and_invert_rules() {
        let config = RouteConfig {
            rules: vec![RouteRule {
                domain_regex: vec![r"^api\d+\.example$".into()],
                source_ip_is_private: true,
                invert: false,
                outbound: Some("proxy".into()),
                ..Default::default()
            }],
            final_outbound: Some("direct".into()),
            ..Default::default()
        };
        let router = Router::compile(&config, "direct").unwrap();
        assert_eq!(
            router.route(&RouteContext {
                domain: Some("api12.example"),
                source_ip: Some("192.168.1.2".parse().unwrap()),
                ..Default::default()
            }),
            RouteDecision::Outbound("proxy".into())
        );
        assert_eq!(
            router.route(&RouteContext {
                domain: Some("www.example"),
                source_ip: Some("192.168.1.2".parse().unwrap()),
                ..Default::default()
            }),
            RouteDecision::Outbound("direct".into())
        );
    }

    #[test]
    fn inline_rule_set_is_used_by_route_rule() {
        let config = RouteConfig {
            rule_set: vec![RuleSetConfig {
                r#type: "inline".into(),
                tag: "ads".into(),
                rules: vec![RouteRule {
                    domain_suffix: vec!["ads.example".into()],
                    ..Default::default()
                }],
                ..Default::default()
            }],
            rules: vec![RouteRule {
                rule_set: vec!["ads".into()],
                action: Some("reject".into()),
                ..Default::default()
            }],
            final_outbound: Some("direct".into()),
            ..Default::default()
        };
        let router = Router::compile(&config, "direct").unwrap();
        assert_eq!(
            router.route(&RouteContext {
                domain: Some("img.ads.example"),
                ..Default::default()
            }),
            RouteDecision::Reject
        );
        assert_eq!(
            router.route(&RouteContext {
                domain: Some("example.com"),
                ..Default::default()
            }),
            RouteDecision::Outbound("direct".into())
        );
    }

    #[test]
    fn tun_route_rule_set_extracts_only_destination_cidrs() {
        let config = RouteConfig {
            rule_set: vec![RuleSetConfig {
                r#type: "inline".into(),
                tag: "router".into(),
                rules: vec![RouteRule {
                    ip_cidr: vec!["192.0.2.0/24".parse().unwrap()],
                    source_ip_cidr: vec!["10.0.0.0/8".parse().unwrap()],
                    ..Default::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        };
        let cidrs = load_rule_set_ip_cidrs(&config, &["router".into()]).unwrap();
        assert_eq!(cidrs, ["192.0.2.0/24".parse().unwrap()]);
        assert!(load_rule_set_ip_cidrs(&config, &["missing".into()]).is_err());
    }

    #[test]
    fn logical_and_or_and_linux_metadata_match() {
        let config: RouteConfig = serde_json::from_str(
            r#"{
              "rules": [{
                "type": "logical",
                "mode": "and",
                "rules": [
                  {"process_name": "curl"},
                  {"type": "logical", "mode": "or", "rules": [
                    {"user_id": 1000},
                    {"network_type": "ethernet"}
                  ]}
                ],
                "outbound": "proxy"
              }],
              "final": "direct"
            }"#,
        )
        .unwrap();
        let router = Router::compile(&config, "direct").unwrap();
        assert_eq!(
            router.route(&RouteContext {
                process_name: Some("curl"),
                user_id: Some(1001),
                network_type: Some("ethernet"),
                ..Default::default()
            }),
            RouteDecision::Outbound("proxy".into())
        );
        assert_eq!(
            router.route(&RouteContext {
                process_name: Some("wget"),
                user_id: Some(1000),
                network_type: Some("ethernet"),
                ..Default::default()
            }),
            RouteDecision::Outbound("direct".into())
        );
    }

    #[test]
    fn non_terminal_actions_continue_to_later_rules() {
        let config: RouteConfig = serde_json::from_str(
            r#"{
              "rules": [
                {"inbound": "mixed-in", "action": "sniff", "sniffer": ["tls", "http"]},
                {"protocol": "tls", "action": "route-options", "override_port": 8443},
                {"protocol": "tls", "outbound": "proxy"}
              ],
              "final": "direct"
            }"#,
        )
        .unwrap();
        let router = Router::compile(&config, "direct").unwrap();
        let context = RouteContext {
            inbound: Some("mixed-in"),
            protocol: Some("tls"),
            ..Default::default()
        };
        assert!(matches!(
            router.next_action(&context, 0),
            Some((0, RuleAction::Sniff { .. }))
        ));
        assert!(matches!(
            router.next_action(&context, 1),
            Some((1, RuleAction::RouteOptions(_)))
        ));
        assert_eq!(
            router.route(&context),
            RouteDecision::Outbound("proxy".into())
        );
    }

    #[test]
    fn package_rules_do_not_match_process_names() {
        let config = RouteConfig {
            rules: vec![RouteRule {
                package_name: vec!["curl".into()],
                outbound: Some("proxy".into()),
                ..Default::default()
            }],
            final_outbound: Some("direct".into()),
            ..Default::default()
        };
        let router = Router::compile(&config, "direct").unwrap();
        assert_eq!(
            router.route(&RouteContext {
                process_name: Some("curl"),
                ..Default::default()
            }),
            RouteDecision::Outbound("direct".into())
        );
        assert_eq!(
            router.route(&RouteContext {
                package_name: Some("curl"),
                ..Default::default()
            }),
            RouteDecision::Outbound("proxy".into())
        );
    }

    #[test]
    fn resolve_carries_cache_ttl_and_client_subnet_options() {
        let config = RouteConfig {
            rules: vec![RouteRule {
                action: Some("resolve".into()),
                rewrite_ttl: Some(60),
                client_subnet: Some("192.0.2.0/24".into()),
                ..Default::default()
            }],
            ..Default::default()
        };
        let router = Router::compile(&config, "direct").unwrap();
        assert!(matches!(
            router.next_action(&RouteContext::default(), 0),
            Some((
                0,
                RuleAction::Resolve {
                    rewrite_ttl: Some(60),
                    client_subnet: Some(subnet),
                    ..
                }
            )) if subnet == "192.0.2.0/24"
        ));
    }

    #[test]
    fn route_defaults_become_direct_dial_options() {
        let config = RouteConfig {
            default_interface: Some("eth0".into()),
            default_mark: Some(123),
            default_network_strategy: Some("prefer_ipv6".into()),
            default_fallback_delay: Some("150ms".into()),
            ..Default::default()
        };
        let router = Router::compile(&config, "direct").unwrap();
        let options = router.default_options();
        assert_eq!(options.bind_interface.as_deref(), Some("eth0"));
        assert_eq!(options.routing_mark, Some(123));
        assert_eq!(options.network_strategy.as_deref(), Some("prefer_ipv6"));
        assert_eq!(options.fallback_delay.as_deref(), Some("150ms"));
    }

    #[test]
    fn linux_metadata_scope_tracks_rule_fields() {
        let empty = Router::compile(&RouteConfig::default(), "direct").unwrap();
        assert!(empty.linux_metadata_scope().is_empty());

        let process = Router::compile(
            &RouteConfig {
                rules: vec![RouteRule {
                    process_name: vec!["curl".into()],
                    outbound: Some("proxy".into()),
                    ..Default::default()
                }],
                ..Default::default()
            },
            "direct",
        )
        .unwrap();
        let scope = process.linux_metadata_scope();
        assert!(scope.process);
        assert!(!scope.user);
        assert!(!scope.interface);
        assert!(!scope.network);

        let user = Router::compile(
            &RouteConfig {
                rules: vec![RouteRule {
                    user_id: vec![1000],
                    outbound: Some("proxy".into()),
                    ..Default::default()
                }],
                ..Default::default()
            },
            "direct",
        )
        .unwrap();
        let scope = user.linux_metadata_scope();
        assert!(scope.user);
        assert!(!scope.process);

        let network = Router::compile(
            &RouteConfig {
                rules: vec![RouteRule {
                    network_type: vec!["wifi".into()],
                    outbound: Some("proxy".into()),
                    ..Default::default()
                }],
                ..Default::default()
            },
            "direct",
        )
        .unwrap();
        let scope = network.linux_metadata_scope();
        assert!(scope.network);
        assert!(!scope.process);
        assert!(!scope.interface);

        let interface = Router::compile(
            &RouteConfig {
                rules: vec![RouteRule {
                    interface_address: HashMap::from([("eth0".into(), vec!["10.0.0.0/24".into()])]),
                    outbound: Some("proxy".into()),
                    ..Default::default()
                }],
                ..Default::default()
            },
            "direct",
        )
        .unwrap();
        let scope = interface.linux_metadata_scope();
        assert!(scope.interface);
        assert!(!scope.process);
        assert!(!scope.network);

        let logical = Router::compile(
            &RouteConfig {
                rules: vec![RouteRule {
                    r#type: "logical".into(),
                    mode: Some("and".into()),
                    rules: vec![RouteRule {
                        source_mac_address: vec!["aa:bb".into()],
                        ..Default::default()
                    }],
                    outbound: Some("proxy".into()),
                    ..Default::default()
                }],
                ..Default::default()
            },
            "direct",
        )
        .unwrap();
        let scope = logical.linux_metadata_scope();
        assert!(scope.mac);
        assert!(!scope.process);
        assert!(!scope.network);
    }
}

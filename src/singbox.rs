//! Sing-box compatible configuration primitives.
//! Unknown fields are intentionally ignored so newer sing-box files remain readable.
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

fn optional_u32_or_string<'de, D>(deserializer: D) -> std::result::Result<Option<u32>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Value {
        Number(u32),
        String(String),
    }

    let Some(value) = Option::<Value>::deserialize(deserializer)? else {
        return Ok(None);
    };
    match value {
        Value::Number(value) => Ok(Some(value)),
        Value::String(value) => {
            let value = value.trim();
            let parsed = value
                .strip_prefix("0x")
                .or_else(|| value.strip_prefix("0X"))
                .map_or_else(|| value.parse(), |hex| u32::from_str_radix(hex, 16))
                .map_err(serde::de::Error::custom)?;
            Ok(Some(parsed))
        }
    }
}

fn one_or_many<'de, D, T>(d: D) -> std::result::Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum V<T> {
        One(T),
        Many(Vec<T>),
    }
    Ok(match V::deserialize(d)? {
        V::One(v) => vec![v],
        V::Many(v) => v,
    })
}

fn string_list_map<'de, D>(
    deserializer: D,
) -> std::result::Result<std::collections::HashMap<String, Vec<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Value {
        One(String),
        Many(Vec<String>),
    }
    Ok(
        std::collections::HashMap::<String, Value>::deserialize(deserializer)?
            .into_iter()
            .map(|(key, value)| {
                (
                    key,
                    match value {
                        Value::One(value) => vec![value],
                        Value::Many(values) => values,
                    },
                )
            })
            .collect(),
    )
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct SingBoxConfig {
    pub log: Option<LogConfig>,
    pub dns: Option<DnsConfig>,
    pub route: Option<RouteConfig>,
    pub inbounds: Vec<Inbound>,
    pub outbounds: Vec<Outbound>,
    pub experimental: Option<ExperimentalConfig>,
    pub http_clients: Vec<HttpClientConfig>,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct HttpClientConfig {
    pub tag: String,
    pub detour: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ExperimentalConfig {
    pub clash_api: Option<ClashApiConfig>,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ClashApiConfig {
    pub external_controller: Option<String>,
    pub external_ui: Option<String>,
    pub external_ui_download_url: Option<String>,
    pub external_ui_download_detour: Option<String>,
    pub secret: Option<String>,
    #[serde(deserialize_with = "one_or_many")]
    pub access_control_allow_origin: Vec<String>,
    pub access_control_allow_private_network: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct LogConfig {
    pub disabled: bool,
    pub level: Option<String>,
    pub output: Option<String>,
    pub timestamp: Option<bool>,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct DnsConfig {
    pub servers: Vec<DnsServer>,
    pub rules: Vec<DnsRule>,
    #[serde(rename = "final")]
    pub final_server: Option<String>,
    pub strategy: Option<String>,
    pub independent_cache: Option<bool>,
    pub disable_cache: Option<bool>,
    pub disable_expire: Option<bool>,
    pub cache_capacity: Option<usize>,
    pub optimistic: Option<serde_json::Value>,
    pub timeout: Option<String>,
    pub reverse_mapping: bool,
    pub client_subnet: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct DnsServer {
    pub r#type: String,
    pub tag: String,
    pub server: Option<String>,
    pub server_port: Option<u16>,
    pub path: Option<String>,
    pub detour: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct DnsRule {
    pub r#type: String,
    pub mode: Option<String>,
    pub rules: Vec<DnsRule>,
    #[serde(deserialize_with = "one_or_many")]
    pub query_type: Vec<serde_json::Value>,
    #[serde(deserialize_with = "one_or_many")]
    pub domain: Vec<String>,
    #[serde(deserialize_with = "one_or_many")]
    pub domain_suffix: Vec<String>,
    #[serde(deserialize_with = "one_or_many")]
    pub domain_keyword: Vec<String>,
    #[serde(deserialize_with = "one_or_many")]
    pub domain_regex: Vec<String>,
    #[serde(deserialize_with = "one_or_many")]
    pub rule_set: Vec<String>,
    pub server: Option<String>,
    pub action: Option<String>,
    pub outbound: Option<String>,
    pub invert: bool,
    pub strategy: Option<String>,
    pub disable_cache: bool,
    pub disable_optimistic_cache: bool,
    pub rewrite_ttl: Option<u32>,
    pub timeout: Option<String>,
    pub client_subnet: Option<String>,
    pub method: Option<String>,
    pub no_drop: bool,
    pub rcode: Option<serde_json::Value>,
    #[serde(deserialize_with = "one_or_many")]
    pub answer: Vec<String>,
    #[serde(deserialize_with = "one_or_many")]
    pub ns: Vec<String>,
    #[serde(deserialize_with = "one_or_many")]
    pub extra: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct RouteConfig {
    pub rules: Vec<RouteRule>,
    pub rule_set: Vec<RuleSetConfig>,
    #[serde(rename = "final")]
    pub final_outbound: Option<String>,
    pub auto_detect_interface: Option<bool>,
    pub default_interface: Option<String>,
    pub default_mark: Option<u32>,
    pub default_network_strategy: Option<String>,
    pub default_fallback_delay: Option<String>,
    pub default_http_client: Option<String>,
    pub default_domain_resolver: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct RouteRule {
    pub r#type: String,
    pub mode: Option<String>,
    pub rules: Vec<RouteRule>,
    #[serde(deserialize_with = "one_or_many")]
    pub domain: Vec<String>,
    #[serde(deserialize_with = "one_or_many")]
    pub domain_suffix: Vec<String>,
    #[serde(deserialize_with = "one_or_many")]
    pub domain_keyword: Vec<String>,
    #[serde(deserialize_with = "one_or_many")]
    pub domain_regex: Vec<String>,
    #[serde(deserialize_with = "one_or_many")]
    pub geosite: Vec<String>,
    #[serde(deserialize_with = "one_or_many")]
    pub geoip: Vec<String>,
    #[serde(deserialize_with = "one_or_many")]
    pub source_geoip: Vec<String>,
    #[serde(deserialize_with = "one_or_many")]
    pub ip_cidr: Vec<String>,
    #[serde(deserialize_with = "one_or_many")]
    pub source_ip_cidr: Vec<String>,
    pub ip_is_private: bool,
    pub source_ip_is_private: bool,
    #[serde(deserialize_with = "one_or_many")]
    pub port: Vec<u16>,
    #[serde(deserialize_with = "one_or_many")]
    pub port_range: Vec<String>,
    #[serde(deserialize_with = "one_or_many")]
    pub network: Vec<String>,
    #[serde(deserialize_with = "one_or_many")]
    pub ip_version: Vec<u8>,
    #[serde(deserialize_with = "one_or_many")]
    pub auth_user: Vec<String>,
    #[serde(deserialize_with = "one_or_many")]
    pub protocol: Vec<String>,
    #[serde(deserialize_with = "one_or_many")]
    pub client: Vec<String>,
    #[serde(deserialize_with = "one_or_many")]
    pub inbound: Vec<String>,
    #[serde(deserialize_with = "one_or_many")]
    pub source_port: Vec<u16>,
    #[serde(deserialize_with = "one_or_many")]
    pub source_port_range: Vec<String>,
    #[serde(deserialize_with = "one_or_many")]
    pub process_name: Vec<String>,
    #[serde(deserialize_with = "one_or_many")]
    pub process_path: Vec<String>,
    #[serde(deserialize_with = "one_or_many")]
    pub process_path_regex: Vec<String>,
    #[serde(deserialize_with = "one_or_many")]
    pub package_name: Vec<String>,
    #[serde(deserialize_with = "one_or_many")]
    pub package_name_regex: Vec<String>,
    #[serde(deserialize_with = "one_or_many")]
    pub user: Vec<String>,
    #[serde(deserialize_with = "one_or_many")]
    pub user_id: Vec<u32>,
    pub clash_mode: Option<String>,
    #[serde(deserialize_with = "one_or_many")]
    pub network_type: Vec<String>,
    pub network_is_expensive: bool,
    pub network_is_constrained: bool,
    #[serde(deserialize_with = "one_or_many")]
    pub wifi_ssid: Vec<String>,
    #[serde(deserialize_with = "one_or_many")]
    pub wifi_bssid: Vec<String>,
    #[serde(deserialize_with = "string_list_map")]
    pub interface_address: std::collections::HashMap<String, Vec<String>>,
    #[serde(deserialize_with = "string_list_map")]
    pub network_interface_address: std::collections::HashMap<String, Vec<String>>,
    #[serde(deserialize_with = "one_or_many")]
    pub default_interface_address: Vec<String>,
    #[serde(deserialize_with = "one_or_many")]
    pub source_mac_address: Vec<String>,
    #[serde(deserialize_with = "one_or_many")]
    pub source_hostname: Vec<String>,
    #[serde(deserialize_with = "one_or_many")]
    pub preferred_by: Vec<String>,
    #[serde(deserialize_with = "one_or_many")]
    pub rule_set: Vec<String>,
    pub rule_set_ip_cidr_match_source: bool,
    pub outbound: Option<String>,
    pub action: Option<String>,
    pub invert: bool,

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

    #[serde(deserialize_with = "one_or_many")]
    pub sniffer: Vec<String>,
    pub timeout: Option<String>,
    pub server: Option<String>,
    pub strategy: Option<String>,
    pub disable_cache: bool,
    pub disable_optimistic_cache: bool,
    pub rewrite_ttl: Option<u32>,
    pub client_subnet: Option<String>,
    pub method: Option<String>,
    pub no_drop: bool,

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
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct RuleSetConfig {
    pub r#type: String,
    pub tag: String,
    pub format: Option<String>,
    pub path: Option<String>,
    pub url: Option<String>,
    pub update_interval: Option<String>,
    pub download_detour: Option<String>,
    pub rules: Vec<RouteRule>,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Inbound {
    pub r#type: String,
    pub tag: Option<String>,
    pub listen: Option<String>,
    pub listen_port: Option<u16>,
    pub users: Vec<User>,
    pub transport: Option<XHttpTransport>,
    pub tls: Option<TlsConfig>,
    pub padding_scheme: Vec<String>,

    // TUN inbound fields.  The data-plane subset is validated by `tun::TunConfig`;
    // keeping the unsupported control-plane fields here prevents them from being
    // silently ignored by the otherwise forward-compatible parser.
    pub interface_name: Option<String>,
    pub netns: Option<String>,
    pub mtu: Option<u16>,
    #[serde(deserialize_with = "one_or_many")]
    pub address: Vec<ipnet::IpNet>,
    pub dns_mode: Option<String>,
    #[serde(deserialize_with = "one_or_many")]
    pub dns_address: Vec<std::net::IpAddr>,
    pub stack: Option<String>,
    pub auto_route: bool,
    pub auto_redirect: bool,
    #[serde(deserialize_with = "optional_u32_or_string")]
    pub auto_redirect_input_mark: Option<u32>,
    #[serde(deserialize_with = "optional_u32_or_string")]
    pub auto_redirect_output_mark: Option<u32>,
    #[serde(deserialize_with = "optional_u32_or_string")]
    pub auto_redirect_reset_mark: Option<u32>,
    pub auto_redirect_nfqueue: Option<u16>,
    pub auto_redirect_iproute2_fallback_rule_index: Option<u32>,
    pub exclude_mptcp: bool,
    #[serde(deserialize_with = "one_or_many")]
    pub loopback_address: Vec<std::net::IpAddr>,
    pub strict_route: bool,
    pub iproute2_table_index: Option<u32>,
    pub iproute2_rule_index: Option<u32>,
    #[serde(deserialize_with = "one_or_many")]
    pub route_address: Vec<ipnet::IpNet>,
    #[serde(deserialize_with = "one_or_many")]
    pub route_address_set: Vec<String>,
    #[serde(deserialize_with = "one_or_many")]
    pub route_exclude_address: Vec<ipnet::IpNet>,
    #[serde(deserialize_with = "one_or_many")]
    pub route_exclude_address_set: Vec<String>,
    #[serde(deserialize_with = "one_or_many")]
    pub include_interface: Vec<String>,
    #[serde(deserialize_with = "one_or_many")]
    pub exclude_interface: Vec<String>,
    #[serde(deserialize_with = "one_or_many")]
    pub include_uid: Vec<u32>,
    #[serde(deserialize_with = "one_or_many")]
    pub include_uid_range: Vec<String>,
    #[serde(deserialize_with = "one_or_many")]
    pub exclude_uid: Vec<u32>,
    #[serde(deserialize_with = "one_or_many")]
    pub exclude_uid_range: Vec<String>,
    #[serde(deserialize_with = "one_or_many")]
    pub include_package: Vec<String>,
    #[serde(deserialize_with = "one_or_many")]
    pub exclude_package: Vec<String>,
    #[serde(deserialize_with = "one_or_many")]
    pub include_android_user: Vec<i32>,
    #[serde(deserialize_with = "one_or_many")]
    pub include_mac_address: Vec<String>,
    #[serde(deserialize_with = "one_or_many")]
    pub exclude_mac_address: Vec<String>,
    pub endpoint_independent_nat: bool,
    pub udp_timeout: Option<String>,
    pub udp_mapping: Option<String>,
    pub udp_filtering: Option<String>,
    pub udp_nat_max: Option<u32>,
    pub platform: Option<serde_json::Value>,
    pub gso: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Outbound {
    pub r#type: String,
    pub tag: Option<String>,
    pub server: Option<String>,
    pub server_port: Option<u16>,
    pub uuid: Option<String>,
    pub flow: Option<String>,
    pub packet_encoding: Option<String>,
    pub transport: Option<XHttpTransport>,
    pub tls: Option<TlsConfig>,
    pub password: Option<String>,
    pub idle_session_check_interval: Option<String>,
    pub idle_session_timeout: Option<String>,
    pub min_idle_session: Option<usize>,
    pub disable_reuse: bool,
    pub outbounds: Vec<String>,
    pub default: Option<String>,
    pub url: Option<String>,
    pub interval: Option<String>,
    pub tolerance: Option<u16>,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct User {
    pub name: Option<String>,
    pub uuid: Option<String>,
    pub password: Option<String>,
    pub flow: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct TlsConfig {
    pub enabled: bool,
    pub server_name: Option<String>,
    pub insecure: bool,
    pub disable_sni: bool,
    pub min_version: Option<String>,
    pub max_version: Option<String>,
    pub certificate: Vec<String>,
    pub key: Vec<String>,
    pub certificate_path: Option<String>,
    pub key_path: Option<String>,
    #[serde(deserialize_with = "one_or_many")]
    pub certificate_public_key_sha256: Vec<String>,
    #[serde(deserialize_with = "one_or_many")]
    pub client_certificate: Vec<String>,
    pub client_certificate_path: Option<String>,
    #[serde(deserialize_with = "one_or_many")]
    pub client_key: Vec<String>,
    pub client_key_path: Option<String>,
    pub client_authentication: Option<String>,
    #[serde(deserialize_with = "one_or_many")]
    pub client_certificate_public_key_sha256: Vec<String>,
    #[serde(deserialize_with = "one_or_many")]
    pub alpn: Vec<String>,
    pub ech: Option<EchConfig>,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct EchConfig {
    pub enabled: bool,
    #[serde(deserialize_with = "one_or_many")]
    pub config: Vec<String>,
    pub config_path: Option<String>,
    pub query_server_name: Option<String>,
    #[serde(deserialize_with = "one_or_many")]
    pub key: Vec<String>,
    pub key_path: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct XHttpRange {
    pub from: usize,
    pub to: usize,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct XHttpTransport {
    pub r#type: String,
    pub host: Option<String>,
    pub path: Option<String>,
    pub mode: Option<crate::config::Mode>,
    pub headers: std::collections::HashMap<String, serde_json::Value>,
    pub x_padding_bytes: Option<XHttpRange>,
    pub x_padding_obfs_mode: bool,
    pub x_padding_key: Option<String>,
    pub x_padding_header: Option<String>,
    pub x_padding_placement: Option<String>,
    pub x_padding_method: Option<String>,
    pub uplink_http_method: Option<String>,
    pub session_id_placement: Option<String>,
    pub session_id_key: Option<String>,
    pub seq_placement: Option<String>,
    pub seq_key: Option<String>,
    pub uplink_data_placement: Option<String>,
    pub uplink_data_key: Option<String>,
    pub sc_max_each_post_bytes: Option<XHttpRange>,
    pub sc_min_posts_interval_ms: Option<XHttpRange>,
    pub sc_max_buffered_posts: Option<usize>,
    pub no_grpc_header: bool,
    pub no_sse_header: bool,
    pub xmux: crate::config::XmuxConfig,
}

impl XHttpTransport {
    pub fn build(&self) -> Result<crate::config::TransportConfig> {
        if self.r#type != "xhttp" {
            bail!("transport must be xhttp")
        }
        let mut c = crate::config::TransportConfig::default();
        if let Some(v) = &self.host {
            c.host = Some(v.clone())
        }
        if let Some(v) = &self.path {
            c.path = v.clone()
        }
        if let Some(v) = self.mode {
            c.mode = v
        }
        c.headers = self
            .headers
            .iter()
            .filter_map(|(k, v)| {
                v.as_str()
                    .map(str::to_owned)
                    .or_else(|| {
                        v.as_array().map(|values| {
                            values
                                .iter()
                                .filter_map(|v| v.as_str())
                                .collect::<Vec<_>>()
                                .join(", ")
                        })
                    })
                    .map(|v| (k.clone(), v))
            })
            .collect();
        if let Some(v) = &self.x_padding_bytes {
            c.padding_min = v.from;
            c.padding_max = v.to
        }
        c.padding_obfs = self.x_padding_obfs_mode;
        if let Some(v) = &self.x_padding_key {
            c.padding_key = v.clone()
        }
        if let Some(v) = &self.x_padding_header {
            c.padding_header = v.clone()
        }
        if let Some(v) = &self.x_padding_placement {
            c.padding_placement = parse_placement(v)?
        }
        if let Some(v) = &self.x_padding_method {
            c.padding_method = v.clone()
        }
        if let Some(v) = &self.uplink_http_method {
            c.uplink_method = v.clone()
        }
        c.no_grpc_header = self.no_grpc_header;
        c.no_sse_header = self.no_sse_header;
        if let Some(v) = &self.session_id_placement {
            c.session_placement = parse_placement(v)?;
            if self.session_id_key.is_none() {
                c.session_key = if c.session_placement == crate::config::Placement::Header {
                    "X-Session"
                } else {
                    "x_session"
                }
                .into()
            }
        }
        if let Some(v) = &self.session_id_key {
            c.session_key = v.clone()
        }
        if let Some(v) = &self.seq_placement {
            c.sequence_placement = parse_placement(v)?;
            if self.seq_key.is_none() {
                c.sequence_key = if c.sequence_placement == crate::config::Placement::Header {
                    "X-Seq"
                } else {
                    "x_seq"
                }
                .into()
            }
        }
        if let Some(v) = &self.seq_key {
            c.sequence_key = v.clone()
        }
        if let Some(v) = &self.uplink_data_placement {
            c.data_placement = parse_placement(v)?;
            if self.uplink_data_key.is_none() {
                c.data_key = if c.data_placement == crate::config::Placement::Cookie {
                    "x_data"
                } else {
                    "X-Data"
                }
                .into()
            }
        }
        if let Some(v) = &self.uplink_data_key {
            c.data_key = v.clone()
        }
        if let Some(v) = &self.sc_max_each_post_bytes {
            c.max_packet_size = if v.to == 0 { v.from } else { v.to }
        }
        if let Some(v) = &self.sc_min_posts_interval_ms {
            c.packet_interval_ms = v.from as u64
        }
        if let Some(v) = self.sc_max_buffered_posts {
            c.max_buffered_packets = v
        }
        c.xmux = self.xmux.clone();
        c.validate()?;
        Ok(c)
    }
}
fn validate_tls_versions(tls: Option<&TlsConfig>) -> Result<()> {
    let Some(tls) = tls else {
        return Ok(());
    };
    for (name, value) in [
        ("min_version", tls.min_version.as_deref()),
        ("max_version", tls.max_version.as_deref()),
    ] {
        if let Some(value) = value {
            crate::tls::parse_tls_version(value)
                .with_context(|| format!("invalid TLS {name}: {value}"))?;
        }
    }
    Ok(())
}

fn parse_placement(v: &str) -> Result<crate::config::Placement> {    Ok(match v {
        "path" => crate::config::Placement::Path,
        "query" => crate::config::Placement::Query,
        "header" => crate::config::Placement::Header,
        "cookie" => crate::config::Placement::Cookie,
        "body" => crate::config::Placement::Body,
        "auto" => crate::config::Placement::Auto,
        "queryInHeader" => crate::config::Placement::QueryInHeader,
        _ => bail!("unsupported XHTTP placement: {v}"),
    })
}
impl SingBoxConfig {
    pub fn from_json(s: &str) -> Result<Self> {
        let c: Self = serde_json::from_str(s)?;
        if c.outbounds.is_empty() && c.inbounds.is_empty() {
            bail!("at least one inbound or outbound is required")
        };
        Ok(c)
    }

    pub fn validate_runtime(&self) -> Result<()> {
        let mut supported = 0usize;
        let has_proxy_inbound = self.inbounds.iter().any(|inbound| {
            matches!(
                inbound.r#type.as_str(),
                "socks" | "http" | "mixed" | "anytls" | "tun"
            )
        });
        for inbound in &self.inbounds {
            supported += self.validate_inbound(inbound)?;
        }
        if supported == 0 {
            bail!("no supported inbound found")
        }
        let mut outbound_tags = std::collections::HashSet::new();
        for outbound in &self.outbounds {
            let tag = outbound.tag.as_deref().unwrap_or(&outbound.r#type);
            if !outbound_tags.insert(tag.to_owned()) {
                bail!("duplicate outbound tag: {tag}")
            }
            if has_proxy_inbound {
                self.validate_outbound(outbound)?;
            }
        }
        for outbound in &self.outbounds {
            if !matches!(outbound.r#type.as_str(), "selector" | "urltest") {
                continue;
            }
            let tag = outbound.tag.as_deref().unwrap_or(&outbound.r#type);
            if outbound.outbounds.is_empty() {
                bail!("{tag} outbound requires at least one member")
            }
            if let Some(default) = &outbound.default
                && !outbound.outbounds.contains(default)
            {
                bail!("{tag} outbound default {default} is not a member")
            }
            for member in &outbound.outbounds {
                if !outbound_tags.contains(member) {
                    bail!("{tag} outbound references unknown outbound: {member}")
                }
            }
        }
        let http_client_tags: std::collections::HashSet<_> =
            self.http_clients.iter().map(|client| &client.tag).collect();
        for client in &self.http_clients {
            if client.tag.is_empty() {
                bail!("http_client requires a tag")
            }
            if let Some(detour) = &client.detour
                && !detour.is_empty()
                && !outbound_tags.contains(detour)
            {
                bail!("http_client {} detour references unknown outbound: {detour}", client.tag)
            }
        }
        if let Some(default_http_client) = self
            .route
            .as_ref()
            .and_then(|route| route.default_http_client.as_deref())
            .filter(|tag| !tag.is_empty())
            && !http_client_tags.iter().any(|tag| tag.as_str() == default_http_client)
        {
            bail!("route default_http_client references unknown http_client: {default_http_client}")
        }
        if let Some(route) = &self.route {
            crate::routing::Router::compile(
                route,
                outbound_tags
                    .iter()
                    .next()
                    .cloned()
                    .unwrap_or_else(|| "direct".into()),
            )?;
            let mut route_tags = Vec::new();
            collect_route_outbounds(&route.rules, &mut route_tags);
            for tag in route_tags.into_iter().chain(route.final_outbound.iter()) {
                if !outbound_tags.contains(tag) {
                    bail!("route references unknown outbound: {tag}")
                }
            }
        }
        if let Some(dns) = &self.dns {
            let rule_set_tags: std::collections::HashSet<_> = self
                .route
                .as_ref()
                .map(|route| route.rule_set.iter().map(|set| &set.tag))
                .into_iter()
                .flatten()
                .collect();
            for rule in &dns.rules {
                for tag in &rule.rule_set {
                    if !rule_set_tags.contains(tag) {
                        bail!("DNS rule references unknown rule-set: {tag}")
                    }
                }
            }
            for server in &dns.servers {
                if let Some(detour) = &server.detour
                    && !detour.is_empty()
                    && !outbound_tags.contains(detour)
                {
                    bail!("DNS server {} detour references unknown outbound: {detour}", server.tag)
                }
            }
            crate::dns::DnsResolver::new(dns)?;
            let tags: std::collections::HashSet<_> =
                dns.servers.iter().map(|server| &server.tag).collect();
            for tag in dns.rules.iter().filter_map(|rule| rule.server.as_ref()) {
                if !tags.contains(tag) {
                    bail!("DNS rule references unknown server: {tag}")
                }
            }
            if let Some(resolver_tag) = self
                .route
                .as_ref()
                .and_then(|route| route.default_domain_resolver.as_deref())
                .filter(|tag| !tag.is_empty())
                && !tags.iter().any(|tag| tag.as_str() == resolver_tag)
            {
                bail!("route default_domain_resolver references unknown DNS server: {resolver_tag}")
            }
        }
        if self
            .experimental
            .as_ref()
            .and_then(|experimental| experimental.clash_api.as_ref())
            .is_some_and(|clash_api| {
                clash_api
                    .external_controller
                    .as_deref()
                    .is_none_or(|value| value.is_empty())
            })
        {
            bail!("clash_api requires external_controller")
        }
        Ok(())
    }

    fn validate_inbound(&self, inbound: &Inbound) -> Result<usize> {
        match inbound.r#type.as_str() {
            "socks" | "http" | "mixed" => {
                inbound
                    .listen_port
                    .context("proxy inbound requires listen_port")?;
                for user in &inbound.users {
                    user.name
                        .as_deref()
                        .filter(|value| !value.is_empty())
                        .context("proxy inbound user requires name")?;
                    user.password
                        .as_deref()
                        .context("proxy inbound user requires password")?;
                }
                if inbound.tls.as_ref().is_some_and(|tls| tls.enabled) {
                    bail!("TLS on proxy inbounds is not supported")
                }
                Ok(1)
            }
            "vless"
                if inbound
                    .transport
                    .as_ref()
                    .is_some_and(|transport| transport.r#type == "xhttp") =>
            {
                inbound
                    .listen_port
                    .context("VLESS XHTTP inbound requires listen_port")?;
                inbound.transport.as_ref().unwrap().build()?;
                if inbound.users.is_empty() {
                    bail!("VLESS XHTTP inbound requires at least one user")
                }
                for user in &inbound.users {
                    uuid::Uuid::parse_str(
                        user.uuid
                            .as_deref()
                            .context("VLESS inbound user requires uuid")?,
                    )
                    .context("invalid VLESS inbound UUID")?;
                    if user.flow.as_deref().is_some_and(|flow| !flow.is_empty()) {
                        bail!("VLESS flow is not supported with XHTTP")
                    }
                }
                if let Some(tls) = inbound.tls.as_ref().filter(|tls| tls.enabled)
                    && (tls.certificate.is_empty() && tls.certificate_path.is_none()
                        || tls.key.is_empty() && tls.key_path.is_none())
                {
                    bail!("TLS inbound requires certificate/key or certificate_path/key_path")
                }
                Ok(1)
            }
            "anytls" => {
                inbound
                    .listen_port
                    .context("AnyTLS inbound requires listen_port")?;
                if inbound.users.is_empty() {
                    bail!("AnyTLS inbound requires at least one user")
                }
                for user in &inbound.users {
                    user.password
                        .as_deref()
                        .filter(|password| !password.is_empty())
                        .context("AnyTLS inbound user requires password")?;
                }
                if !inbound.padding_scheme.is_empty() {
                    anytls::PaddingScheme::parse(inbound.padding_scheme.join("\n").as_bytes())
                        .context("invalid AnyTLS padding_scheme")?;
                }
                if let Some(tls) = inbound.tls.as_ref().filter(|tls| tls.enabled) {
                    if tls.certificate.is_empty() && tls.certificate_path.is_none()
                        || tls.key.is_empty() && tls.key_path.is_none()
                    {
                        bail!("AnyTLS TLS inbound requires certificate and key")
                    }
                    crate::anytls::validate_server_tls(tls)?;
                }
                if let Some(ech) = inbound
                    .tls
                    .as_ref()
                    .and_then(|tls| tls.ech.as_ref())
                    .filter(|ech| ech.enabled)
                {
                    if !ech.key.is_empty() && ech.key_path.is_some() {
                        bail!("ECH key and key_path are mutually exclusive")
                    }
                    if ech.key.is_empty() && ech.key_path.is_none() {
                        bail!("AnyTLS ECH inbound requires key or key_path")
                    }
                }
                Ok(1)
            }
            "tun" => {
                crate::tun::TunConfig::from_inbound(inbound)?;
                Ok(1)
            }
            _ => Ok(0),
        }
    }

    fn validate_outbound(&self, outbound: &Outbound) -> Result<()> {
        validate_tls_versions(outbound.tls.as_ref())?;
        match outbound.r#type.as_str() {
            "direct" | "block" | "selector" | "urltest" => {}
            "vless" => {
                outbound
                    .server
                    .as_ref()
                    .context("VLESS outbound requires server")?;
                uuid::Uuid::parse_str(
                    outbound
                        .uuid
                        .as_deref()
                        .context("VLESS outbound requires uuid")?,
                )
                .context("invalid VLESS outbound UUID")?;
                if outbound
                    .flow
                    .as_deref()
                    .is_some_and(|flow| !flow.is_empty())
                {
                    bail!("VLESS flow is not supported with XHTTP")
                }
                outbound
                    .transport
                    .as_ref()
                    .context("VLESS outbound requires XHTTP transport")?
                    .build()?;
                if let Some(ech) = outbound.tls.as_ref().and_then(|tls| tls.ech.as_ref())
                    && ech.enabled
                {
                    if !ech.config.is_empty() && ech.config_path.is_some() {
                        bail!("ECH config and config_path are mutually exclusive")
                    }
                    let pem = if !ech.config.is_empty() {
                        ech.config.join("\n").into_bytes()
                    } else if let Some(path) = &ech.config_path {
                        std::fs::read(path).context("read ECH config")?
                    } else if self.dns.is_none() {
                        bail!("DNS-discovered ECH requires a DNS configuration")
                    } else {
                        Vec::new()
                    };
                    if !pem.is_empty() {
                        crate::tls::parse_ech_config(&pem)?;
                    }
                }
                if !matches!(
                    outbound.packet_encoding.as_deref(),
                    None | Some("") | Some("xudp")
                ) {
                    bail!("unsupported VLESS packet_encoding")
                }
            }
            "anytls" => {
                outbound
                    .server
                    .as_ref()
                    .context("AnyTLS outbound requires server")?;
                outbound
                    .password
                    .as_deref()
                    .filter(|password| !password.is_empty())
                    .context("AnyTLS outbound requires password")?;
                if !outbound.tls.as_ref().is_some_and(|tls| tls.enabled) {
                    bail!("AnyTLS outbound requires TLS")
                }
                if let Some(ech) = outbound
                    .tls
                    .as_ref()
                    .and_then(|tls| tls.ech.as_ref())
                    .filter(|ech| ech.enabled)
                {
                    if !ech.config.is_empty() && ech.config_path.is_some() {
                        bail!("ECH config and config_path are mutually exclusive")
                    }
                    if !ech.config.is_empty() {
                        crate::tls::parse_ech_config(ech.config.join("\n").as_bytes())?;
                    } else if let Some(path) = &ech.config_path {
                        crate::tls::parse_ech_config(
                            &std::fs::read(path).context("read ECH config")?,
                        )?;
                    } else if self.dns.is_none() {
                        bail!("DNS-discovered ECH requires a DNS configuration")
                    }
                }
                crate::anytls::validate_outbound(outbound)?;
            }
            value => bail!("unsupported outbound type for proxy inbound: {value}"),
        }
        Ok(())
    }
}

fn collect_route_outbounds<'a>(rules: &'a [RouteRule], result: &mut Vec<&'a String>) {
    for rule in rules {
        if let Some(outbound) = &rule.outbound {
            result.push(outbound);
        }
        collect_route_outbounds(&rule.rules, result);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_repository_singbox_config() {
        let c =
            SingBoxConfig::from_json(include_str!("../tests/interop-rust-server.json")).unwrap();
        let inbound = c
            .inbounds
            .iter()
            .find(|v| v.tag.as_deref() == Some("vless-xhttp-in"))
            .unwrap();
        assert_eq!(inbound.transport.as_ref().unwrap().r#type, "xhttp");
        assert_eq!(inbound.users.len(), 1);
    }
    #[test]
    fn listable_route_fields_accept_scalars() {
        let c=SingBoxConfig::from_json(r#"{"inbounds":[{"type":"socks","listen_port":1080}],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"rules":[{"domain_suffix":"example.com","port":443,"outbound":"direct"}]}}"#).unwrap();
        assert_eq!(c.route.unwrap().rules[0].port, vec![443]);
    }

    #[test]
    fn xmux_accepts_sing_box_and_xray_field_names() {
        for xmux in [
            r#"{"max_concurrency":{"from":2,"to":4},"h_max_request_times":{"from":8,"to":16}}"#,
            r#"{"maxConcurrency":{"from":2,"to":4},"hMaxRequestTimes":{"from":8,"to":16}}"#,
        ] {
            let json = format!(r#"{{"type":"xhttp","xmux":{xmux}}}"#,);
            let transport: XHttpTransport = serde_json::from_str(&json).unwrap();
            let built = transport.build().unwrap();
            assert_eq!(built.xmux.max_concurrency.from, 2);
            assert_eq!(built.xmux.h_max_request_times.to, 16);
        }
    }

    #[test]
    fn conflicting_xmux_limits_are_rejected() {
        let transport: XHttpTransport = serde_json::from_str(
            r#"{"type":"xhttp","xmux":{"max_connections":{"from":1,"to":1},"max_concurrency":{"from":1,"to":1}}}"#,
        )
        .unwrap();
        assert!(transport.build().is_err());
    }

    #[test]
    fn validates_anytls_client_and_server_configuration() {
        let config = SingBoxConfig::from_json(
            r#"{
                "inbounds":[{
                    "type":"anytls","listen_port":8443,
                    "users":[{"name":"user","password":"secret"}],
                    "padding_scheme":["stop=2","0=30-30","1=100-200"]
                }],
                "outbounds":[{
                    "type":"anytls","tag":"proxy","server":"example.com",
                    "server_port":443,"password":"secret",
                    "idle_session_timeout":"45s",
                    "tls":{"enabled":true,"insecure":true}
                }]
            }"#,
        )
        .unwrap();
        config.validate_runtime().unwrap();
    }

    #[test]
    fn rejects_incomplete_anytls_configuration() {
        let config = SingBoxConfig::from_json(
            r#"{
                "inbounds":[{"type":"socks","listen_port":1080}],
                "outbounds":[{"type":"anytls","server":"example.com","tls":{"enabled":true}}]
            }"#,
        )
        .unwrap();
        assert!(config.validate_runtime().is_err());
    }

    #[test]
    fn rejects_invalid_anytls_padding_and_session_durations() {
        let invalid_padding = SingBoxConfig::from_json(
            r#"{
                "inbounds":[{
                    "type":"anytls","listen_port":8443,
                    "users":[{"password":"secret"}],
                    "padding_scheme":["0=30-30"]
                }]
            }"#,
        )
        .unwrap();
        assert!(
            invalid_padding
                .validate_runtime()
                .unwrap_err()
                .to_string()
                .contains("invalid AnyTLS padding_scheme")
        );

        let invalid_duration = SingBoxConfig::from_json(
            r#"{
                "inbounds":[{"type":"socks","listen_port":1080}],
                "outbounds":[{
                    "type":"anytls","server":"example.com","password":"secret",
                    "idle_session_timeout":"forever",
                    "tls":{"enabled":true,"insecure":true}
                }]
            }"#,
        )
        .unwrap();
        assert!(
            invalid_duration
                .validate_runtime()
                .unwrap_err()
                .to_string()
                .contains("invalid AnyTLS duration")
        );
    }

    #[test]
    fn rejects_incomplete_or_conflicting_anytls_ech() {
        for (ech, expected) in [
            (
                r#"{"enabled":true}"#,
                "DNS-discovered ECH requires a DNS configuration",
            ),
            (
                r#"{"enabled":true,"config":["dummy"],"config_path":"ech.pem"}"#,
                "ECH config and config_path are mutually exclusive",
            ),
        ] {
            let config = SingBoxConfig::from_json(&format!(
                r#"{{
                    "inbounds":[{{"type":"socks","listen_port":1080}}],
                    "outbounds":[{{
                        "type":"anytls","server":"example.com","password":"secret",
                        "tls":{{"enabled":true,"insecure":true,"ech":{ech}}}
                    }}]
                }}"#
            ))
            .unwrap();
            assert!(
                config
                    .validate_runtime()
                    .unwrap_err()
                    .to_string()
                    .contains(expected),
                "{expected}"
            );
        }
    }

    #[test]
    fn selector_and_urltest_outbounds_validate_members() {
        let valid = r#"{
            "inbounds":[{"type":"socks","listen_port":1080}],
            "outbounds":[
                {"type":"direct","tag":"direct"},
                {"type":"selector","tag":"proxy","outbounds":["direct"],"default":"direct"},
                {"type":"urltest","tag":"auto","outbounds":["direct"],"url":"http://gstatic.com/generate_204"}
            ]
        }"#;
        let config = SingBoxConfig::from_json(valid).unwrap();
        config.validate_runtime().unwrap();

        // Empty member list is rejected.
        let empty = valid.replace("\"outbounds\":[\"direct\"]", "\"outbounds\":[]");
        let config = SingBoxConfig::from_json(&empty).unwrap();
        assert!(config.validate_runtime().is_err());

        // Unknown member is rejected.
        let bad = valid.replace("\"outbounds\":[\"direct\"]", "\"outbounds\":[\"ghost\"]");
        let config = SingBoxConfig::from_json(&bad).unwrap();
        assert!(config.validate_runtime().is_err());

        // Selector default that is not a member is rejected.
        let bad_default = valid.replace("\"default\":\"direct\"", "\"default\":\"ghost\"");
        let config = SingBoxConfig::from_json(&bad_default).unwrap();
        assert!(config.validate_runtime().is_err());
    }
}

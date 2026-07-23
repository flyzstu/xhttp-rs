use std::{collections::HashMap, time::Duration};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct RangeConfig {
    pub from: usize,
    pub to: usize,
}

impl RangeConfig {
    pub fn validate(self, name: &str) -> Result<()> {
        if self.to == 0 {
            if self.from != 0 {
                bail!("{name}.from requires a non-zero to value");
            }
        } else if self.from > self.to {
            bail!("{name}.from must not exceed {name}.to");
        }
        Ok(())
    }

    pub fn sample(self) -> usize {
        if self.to == 0 {
            0
        } else {
            rand::random_range(self.from..=self.to)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct XmuxConfig {
    #[serde(alias = "maxConcurrency")]
    pub max_concurrency: RangeConfig,
    #[serde(alias = "maxConnections")]
    pub max_connections: RangeConfig,
    #[serde(alias = "cMaxReuseTimes")]
    pub c_max_reuse_times: RangeConfig,
    #[serde(alias = "hMaxRequestTimes")]
    pub h_max_request_times: RangeConfig,
    #[serde(alias = "hMaxReusableSecs")]
    pub h_max_reusable_secs: RangeConfig,
    #[serde(alias = "hKeepAlivePeriod")]
    pub h_keep_alive_period: u64,
}

impl XmuxConfig {
    pub fn validate(&self) -> Result<()> {
        if self.max_concurrency.to != 0 && self.max_connections.to != 0 {
            bail!("xmux max_concurrency and max_connections are mutually exclusive");
        }
        for (name, range) in [
            ("xmux.max_concurrency", self.max_concurrency),
            ("xmux.max_connections", self.max_connections),
            ("xmux.c_max_reuse_times", self.c_max_reuse_times),
            ("xmux.h_max_request_times", self.h_max_request_times),
            ("xmux.h_max_reusable_secs", self.h_max_reusable_secs),
        ] {
            range.validate(name)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    #[default]
    Auto,
    StreamOne,
    StreamUp,
    PacketUp,
}

impl Mode {
    pub fn resolved(self) -> Self {
        match self {
            Self::Auto => Self::PacketUp,
            mode => mode,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub enum Placement {
    #[default]
    Path,
    Query,
    Header,
    Cookie,
    Body,
    Auto,
    QueryInHeader,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TransportConfig {
    pub path: String,
    pub query: Option<String>,
    pub host: Option<String>,
    pub mode: Mode,
    pub headers: HashMap<String, String>,
    pub token: Option<String>,
    pub session_placement: Placement,
    pub session_key: String,
    pub sequence_placement: Placement,
    pub sequence_key: String,
    pub data_placement: Placement,
    pub data_key: String,
    pub padding_min: usize,
    pub padding_max: usize,
    pub padding_obfs: bool,
    pub padding_placement: Placement,
    pub padding_key: String,
    pub padding_header: String,
    pub padding_method: String,
    pub uplink_method: String,
    pub no_grpc_header: bool,
    pub no_sse_header: bool,
    pub max_packet_size: usize,
    pub max_buffered_packets: usize,
    pub packet_interval_ms: u64,
    pub session_timeout_secs: u64,
    pub max_sessions: usize,
    pub max_session_id_length: usize,
    pub xmux: XmuxConfig,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            path: "/xhttp".into(),
            query: None,
            host: None,
            mode: Mode::Auto,
            headers: HashMap::new(),
            token: None,
            session_placement: Placement::Path,
            session_key: "x_session".into(),
            sequence_placement: Placement::Path,
            sequence_key: "x_seq".into(),
            data_placement: Placement::Body,
            data_key: "X-Data".into(),
            padding_min: 100,
            padding_max: 1000,
            padding_obfs: false,
            padding_placement: Placement::QueryInHeader,
            padding_key: "x_padding".into(),
            padding_header: "X-Padding".into(),
            padding_method: "repeat-x".into(),
            uplink_method: "POST".into(),
            no_grpc_header: false,
            no_sse_header: false,
            max_packet_size: 1_000_000,
            max_buffered_packets: 30,
            packet_interval_ms: 30,
            session_timeout_secs: 30,
            max_sessions: 4096,
            max_session_id_length: 256,
            xmux: XmuxConfig::default(),
        }
    }
}

impl TransportConfig {
    pub fn validate(&mut self) -> Result<()> {
        if let Some((path, query)) = self.path.split_once('?') {
            let path = path.to_owned();
            let query = query.to_owned();
            self.path = path;
            if !query.is_empty() {
                self.query = Some(query);
            }
        }
        if !self.path.starts_with('/') {
            self.path.insert(0, '/');
        }
        while self.path.len() > 1 && self.path.ends_with('/') {
            self.path.pop();
        }
        if self.padding_min > self.padding_max {
            bail!("padding_min must not exceed padding_max");
        }
        if self.max_packet_size == 0
            || self.max_buffered_packets == 0
            || self.session_timeout_secs == 0
            || self.max_sessions == 0
            || self.max_session_id_length == 0
        {
            bail!("packet limits must be greater than zero");
        }
        if !matches!(
            self.session_placement,
            Placement::Path | Placement::Query | Placement::Header | Placement::Cookie
        ) || !matches!(
            self.sequence_placement,
            Placement::Path | Placement::Query | Placement::Header | Placement::Cookie
        ) {
            bail!("session and sequence metadata cannot use body placement");
        }
        if !matches!(
            self.data_placement,
            Placement::Body | Placement::Header | Placement::Cookie | Placement::Auto
        ) {
            bail!("data placement must be body, header, cookie, or auto");
        }
        if !matches!(
            self.padding_placement,
            Placement::Header | Placement::Cookie | Placement::Query | Placement::QueryInHeader
        ) {
            bail!("invalid padding placement")
        }
        if !matches!(self.padding_method.as_str(), "repeat-x" | "tokenish") {
            bail!("invalid padding method")
        }
        self.uplink_method = self.uplink_method.to_ascii_uppercase();
        let method = axum::http::Method::from_bytes(self.uplink_method.as_bytes())
            .context("invalid XHTTP uplink method")?;
        if method == axum::http::Method::GET && !matches!(self.mode, Mode::Auto | Mode::PacketUp) {
            bail!("GET uplink method requires packet-up or auto mode")
        }
        for (name, value) in &self.headers {
            if name.eq_ignore_ascii_case("host") {
                bail!("use the XHTTP host field instead of a Host header")
            }
            axum::http::HeaderName::try_from(name).context("invalid XHTTP header name")?;
            axum::http::HeaderValue::try_from(value).context("invalid XHTTP header value")?;
        }
        if let Some(host) = &self.host {
            axum::http::HeaderValue::try_from(host).context("invalid XHTTP host value")?;
        }
        if let Some(token) = &self.token {
            axum::http::HeaderValue::try_from(format!("Bearer {token}"))
                .context("invalid XHTTP authorization token")?;
        }
        self.xmux.validate()?;
        for (placement, key) in [
            (self.session_placement, &self.session_key),
            (self.sequence_placement, &self.sequence_key),
        ] {
            if placement == Placement::Header {
                axum::http::HeaderName::try_from(key).context("invalid metadata header name")?;
            }
        }
        Ok(())
    }

    pub fn session_timeout(&self) -> Duration {
        Duration::from_secs(self.session_timeout_secs)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub listen: String,
    #[serde(default)]
    pub target: String,
    #[serde(default)]
    pub users: Vec<String>,
    #[serde(default)]
    pub transport: TransportConfig,
    pub tls: Option<ServerTlsConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerTlsConfig {
    pub certificate: String,
    pub private_key: String,
    #[serde(default)]
    pub http3: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    pub listen: String,
    pub server: String,
    #[serde(default)]
    pub connect_addr: Option<std::net::SocketAddr>,
    #[serde(default)]
    pub transport: TransportConfig,
    #[serde(default)]
    pub tls: ClientTlsConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ClientTlsConfig {
    pub insecure: bool,
    pub ca_certificate: Option<String>,
    pub ca_pem: Option<String>,
    pub http2_only: bool,
    pub http3: bool,
    pub ech_config: Option<String>,
    pub ech_config_path: Option<String>,
}

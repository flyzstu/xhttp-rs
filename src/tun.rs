//! Tokio-driven TUN inbound backed by a userspace smoltcp network stack.
//!
//! The device and network stack deliberately remain separate, matching the
//! xhttp-box lifecycle: create/configure the L3 device first, then attach the
//! TCP/UDP stack and route extracted flows through the normal dispatcher.

use crate::{
    proxy::{self, ProxyRuntime},
    singbox::{DnsConfig, Inbound, Outbound, RouteConfig},
};
use anyhow::{Context, Result, bail};
use futures_util::{SinkExt, StreamExt};
use ipnet::IpNet;
use netstack_smoltcp::StackBuilder;
use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex, Weak},
};
use tokio::sync::mpsc;

const DEFAULT_MTU: u16 = 9000;
const MAX_PACKET_SIZE: usize = 65_535;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunConfig {
    pub interface_name: String,
    pub mtu: u16,
    pub addresses: Vec<IpNet>,
    pub stack: String,
    pub auto_route: bool,
    pub auto_redirect: bool,
    pub strict_route: bool,
    pub route_addresses: Vec<IpNet>,
    pub route_exclude_addresses: Vec<IpNet>,
    pub route_include_active: bool,
    pub route_exclude_active: bool,
    pub include_interfaces: Vec<String>,
    pub exclude_interfaces: Vec<String>,
    pub include_uids: Vec<u32>,
    pub exclude_uids: Vec<u32>,
    pub include_uid_ranges: Vec<(u32, u32)>,
    pub exclude_uid_ranges: Vec<(u32, u32)>,
    pub table_index: u32,
    pub rule_index: u32,
    pub redirect_input_mark: u32,
    pub redirect_output_mark: u32,
    pub include_macs: Vec<String>,
    pub exclude_macs: Vec<String>,
    pub bypass_addresses: Vec<IpAddr>,
    pub udp_timeout: std::time::Duration,
    pub udp_mapping: UdpNatBehavior,
    pub udp_filtering: UdpNatBehavior,
    pub udp_nat_max: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpNatBehavior {
    EndpointIndependent,
    AddressDependent,
    AddressAndPortDependent,
}

impl UdpNatBehavior {
    fn parse(value: Option<&str>, field: &str) -> Result<Self> {
        match value.unwrap_or("endpoint_independent") {
            "endpoint_independent" => Ok(Self::EndpointIndependent),
            "address_dependent" => Ok(Self::AddressDependent),
            "address_and_port_dependent" => Ok(Self::AddressAndPortDependent),
            value => bail!("unsupported TUN {field}: {value}"),
        }
    }
}

impl TunConfig {
    pub fn from_inbound(inbound: &Inbound) -> Result<Self> {
        if inbound.r#type != "tun" {
            bail!("TUN configuration requires type=tun")
        }
        #[cfg(not(target_os = "linux"))]
        bail!("TUN inbound is currently supported on Linux only");

        if inbound.auto_redirect && !inbound.auto_route {
            bail!("TUN auto_redirect requires auto_route")
        }
        if inbound.strict_route && !inbound.auto_route {
            bail!("TUN strict_route requires auto_route")
        }
        if (!inbound.route_address.is_empty()
            || !inbound.route_exclude_address.is_empty()
            || !inbound.include_interface.is_empty()
            || !inbound.exclude_interface.is_empty()
            || !inbound.include_uid.is_empty()
            || !inbound.exclude_uid.is_empty()
            || !inbound.include_uid_range.is_empty()
            || !inbound.exclude_uid_range.is_empty())
            && !inbound.auto_route
        {
            bail!("TUN route/interface/UID selectors require auto_route")
        }
        if !inbound.include_interface.is_empty() && !inbound.exclude_interface.is_empty() {
            bail!("TUN include_interface and exclude_interface are mutually exclusive")
        }
        if (!inbound.include_uid.is_empty() || !inbound.include_uid_range.is_empty())
            && !inbound.auto_redirect
        {
            bail!(
                "TUN include_uid requires auto_redirect so proxy-owned sockets can be marked for bypass"
            )
        }
        if (!inbound.include_mac_address.is_empty() || !inbound.exclude_mac_address.is_empty())
            && !inbound.auto_redirect
        {
            bail!("TUN MAC filters require auto_redirect")
        }
        if !inbound.include_package.is_empty() || !inbound.exclude_package.is_empty() {
            bail!("TUN package filters are Android-only and unavailable on Linux")
        }
        if !inbound.include_android_user.is_empty() {
            bail!("TUN include_android_user is Android-only and unavailable on Linux")
        }
        if inbound
            .dns_mode
            .as_deref()
            .is_some_and(|mode| mode != "disabled")
            || !inbound.dns_address.is_empty()
        {
            bail!("TUN dns_mode/dns_address is not implemented; use route DNS hijack rules")
        }
        if inbound.auto_redirect_reset_mark.is_some()
            || inbound.auto_redirect_nfqueue.is_some()
            || inbound.auto_redirect_iproute2_fallback_rule_index.is_some()
        {
            bail!(
                "TUN NFQUEUE reset/fallback options do not apply to the native nftables mark path"
            )
        }
        if inbound.exclude_mptcp {
            bail!("TUN exclude_mptcp is not implemented")
        }
        if !inbound.loopback_address.is_empty() {
            bail!("TUN loopback_address remapping is not implemented")
        }
        if inbound.platform.is_some() {
            bail!("TUN platform options are unavailable on native Linux")
        }
        if inbound.gso {
            bail!("deprecated TUN gso option is not implemented")
        }
        if inbound.endpoint_independent_nat {
            bail!(
                "deprecated endpoint_independent_nat is not supported; use UDP mapping/filtering options"
            )
        }
        if inbound.netns.is_some() {
            bail!("TUN network namespace support is not implemented yet")
        }
        let addresses = inbound.address.clone();
        if addresses.is_empty() {
            bail!("TUN inbound requires at least one address prefix")
        }
        let ipv4_count = addresses
            .iter()
            .filter(|value| value.addr().is_ipv4())
            .count();
        if ipv4_count > 1 {
            bail!("TUN device currently accepts at most one IPv4 address")
        }
        let mtu = inbound.mtu.unwrap_or(DEFAULT_MTU);
        if !(1280..=u16::MAX).contains(&mtu) {
            bail!("TUN mtu must be between 1280 and 65535")
        }
        let stack = inbound.stack.clone().unwrap_or_else(|| "mixed".into());
        if !matches!(stack.as_str(), "mixed" | "gvisor" | "smoltcp") {
            bail!("unsupported TUN stack {stack}; expected mixed, gvisor or smoltcp")
        }
        let table_index = inbound.iproute2_table_index.unwrap_or(2022);
        if table_index == 0 || matches!(table_index, 253..=255) {
            bail!("TUN iproute2_table_index must be a non-reserved table number")
        }
        let rule_index = inbound.iproute2_rule_index.unwrap_or(9000);
        rule_index
            .checked_add(63)
            .filter(|value| *value < 32766)
            .context("TUN iproute2_rule_index leaves no room for managed rules")?;
        for ipv6 in [false, true] {
            let local_source_rules =
                if inbound.include_uid.is_empty() && inbound.include_uid_range.is_empty() {
                    inbound
                        .address
                        .iter()
                        .filter(|prefix| prefix.addr().is_ipv6() == ipv6)
                        .count()
                        + 1
                } else {
                    inbound.include_uid.len() + inbound.include_uid_range.len()
                };
            let family_rules = inbound
                .route_exclude_address
                .iter()
                .filter(|prefix| prefix.addr().is_ipv6() == ipv6)
                .count()
                + inbound.exclude_uid.len()
                + inbound.exclude_uid_range.len()
                + inbound.exclude_interface.len()
                + 1
                + local_source_rules
                + inbound.include_interface.len().max(1);
            if family_rules > 64 {
                bail!("TUN auto_route selectors exceed the 64-rule managed priority window")
            }
        }
        let redirect_input_mark = inbound.auto_redirect_input_mark.unwrap_or(0x2023);
        let redirect_output_mark = inbound.auto_redirect_output_mark.unwrap_or(0x2024);
        if redirect_input_mark == 0
            || redirect_output_mark == 0
            || redirect_input_mark == redirect_output_mark
        {
            bail!("TUN auto_redirect input/output marks must be distinct and non-zero")
        }
        for mac in inbound
            .include_mac_address
            .iter()
            .chain(&inbound.exclude_mac_address)
        {
            parse_mac(mac).with_context(|| format!("invalid TUN MAC address: {mac}"))?;
        }
        let include_uid_ranges =
            parse_uid_ranges(&inbound.include_uid_range).context("parse TUN include_uid_range")?;
        let exclude_uid_ranges =
            parse_uid_ranges(&inbound.exclude_uid_range).context("parse TUN exclude_uid_range")?;
        let udp_timeout = inbound
            .udp_timeout
            .as_deref()
            .map(parse_duration)
            .transpose()
            .context("parse TUN udp_timeout")?
            .unwrap_or_else(|| std::time::Duration::from_secs(300));
        if udp_timeout.is_zero() {
            bail!("TUN udp_timeout must be greater than zero")
        }
        let udp_nat_max = match inbound.udp_nat_max.unwrap_or(0) {
            0 => default_udp_nat_max(),
            value => value as usize,
        };
        Ok(Self {
            interface_name: inbound
                .interface_name
                .clone()
                .unwrap_or_else(|| "xhttp0".into()),
            mtu,
            addresses,
            stack,
            auto_route: inbound.auto_route,
            auto_redirect: inbound.auto_redirect,
            strict_route: inbound.strict_route,
            route_addresses: inbound.route_address.clone(),
            route_exclude_addresses: inbound.route_exclude_address.clone(),
            route_include_active: !inbound.route_address.is_empty()
                || !inbound.route_address_set.is_empty(),
            route_exclude_active: !inbound.route_exclude_address.is_empty()
                || !inbound.route_exclude_address_set.is_empty(),
            include_interfaces: inbound.include_interface.clone(),
            exclude_interfaces: inbound.exclude_interface.clone(),
            include_uids: inbound.include_uid.clone(),
            exclude_uids: inbound.exclude_uid.clone(),
            include_uid_ranges,
            exclude_uid_ranges,
            table_index,
            rule_index,
            redirect_input_mark,
            redirect_output_mark,
            include_macs: inbound.include_mac_address.clone(),
            exclude_macs: inbound.exclude_mac_address.clone(),
            bypass_addresses: Vec::new(),
            udp_timeout,
            udp_mapping: UdpNatBehavior::parse(inbound.udp_mapping.as_deref(), "udp_mapping")?,
            udp_filtering: UdpNatBehavior::parse(
                inbound.udp_filtering.as_deref(),
                "udp_filtering",
            )?,
            udp_nat_max,
        })
    }
}

fn parse_uid_ranges(values: &[String]) -> Result<Vec<(u32, u32)>> {
    values
        .iter()
        .map(|value| {
            let (start, end) = value
                .split_once(':')
                .with_context(|| format!("UID range {value:?} is missing ':'"))?;
            let start = start
                .parse::<u32>()
                .with_context(|| format!("invalid UID range start in {value:?}"))?;
            let end = end
                .parse::<u32>()
                .with_context(|| format!("invalid UID range end in {value:?}"))?;
            if start > end {
                bail!("UID range start exceeds end in {value:?}")
            }
            Ok((start, end))
        })
        .collect()
}

fn parse_duration(value: &str) -> Result<std::time::Duration> {
    let split = value
        .find(|character: char| !character.is_ascii_digit())
        .unwrap_or(value.len());
    let amount = value[..split]
        .parse::<u64>()
        .with_context(|| format!("invalid duration {value:?}"))?;
    Ok(match &value[split..] {
        "ms" => std::time::Duration::from_millis(amount),
        "s" | "" => std::time::Duration::from_secs(amount),
        "m" => std::time::Duration::from_secs(amount.saturating_mul(60)),
        "h" => std::time::Duration::from_secs(amount.saturating_mul(3600)),
        "d" => std::time::Duration::from_secs(amount.saturating_mul(86400)),
        unit => bail!("unsupported duration unit {unit:?}"),
    })
}

fn default_udp_nat_max() -> usize {
    std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|value| {
            value.lines().find_map(|line| {
                line.strip_prefix("MemTotal:")?
                    .split_whitespace()
                    .next()?
                    .parse::<usize>()
                    .ok()
            })
        })
        .map(|kibibytes| (kibibytes.saturating_mul(1024) / 16_384).clamp(4096, 16_384))
        .unwrap_or(16_384)
}

pub async fn run(
    inbound: Inbound,
    outbounds: Vec<Outbound>,
    route: Option<RouteConfig>,
    dns: Option<DnsConfig>,
    http_clients: Vec<crate::singbox::HttpClientConfig>,
    dns_cache_path: Option<std::path::PathBuf>,
) -> Result<()> {
    let mut config = TunConfig::from_inbound(&inbound)?;
    let static_route_addresses = config.route_addresses.clone();
    let static_route_exclude_addresses = config.route_exclude_addresses.clone();
    let tag = inbound.tag.as_deref().unwrap_or("tun-in").to_owned();
    if config.auto_redirect {
        config.bypass_addresses = collect_bypass_addresses(&outbounds, dns.as_ref()).await;
    }
    let mut route = route.unwrap_or_default();
    if !inbound.route_address_set.is_empty() || !inbound.route_exclude_address_set.is_empty() {
        let route_config = route.clone();
        let include_tags = inbound.route_address_set.clone();
        let exclude_tags = inbound.route_exclude_address_set.clone();
        let (include, exclude) = tokio::task::spawn_blocking(move || {
            Ok::<_, anyhow::Error>((
                crate::routing::load_rule_set_ip_cidrs(&route_config, &include_tags)?,
                crate::routing::load_rule_set_ip_cidrs(&route_config, &exclude_tags)?,
            ))
        })
        .await
        .context("TUN route rule-set loader task failed")??;
        config.route_addresses.extend(include);
        config.route_exclude_addresses.extend(exclude);
        config.route_addresses.sort_by_key(ToString::to_string);
        config.route_addresses.dedup();
        config
            .route_exclude_addresses
            .sort_by_key(ToString::to_string);
        config.route_exclude_addresses.dedup();
    }
    if route.default_interface.is_none() && route.auto_detect_interface != Some(false) {
        // Resolve before creating the TUN device so direct outbound sockets bind
        // the physical default interface and cannot loop back into the TUN route.
        route.default_interface = crate::linux_route::default_interface();
        route
            .default_interface
            .as_deref()
            .context("detect physical default interface before starting TUN")?;
        route.auto_detect_interface = Some(false);
    }
    let rule_set_route = route.clone();
    let mut runtime = proxy::build_runtime(outbounds, Some(route), dns, http_clients, dns_cache_path).await?;
    if config.auto_redirect {
        runtime.set_tun_output_mark(config.redirect_output_mark);
    }
    let runtime = Arc::new(runtime);
    let device = Arc::new(build_device(&config)?);
    let redirect_guard = config
        .auto_redirect
        .then(|| crate::tun_redirect_linux::LinuxTunRedirect::install(&config))
        .transpose()?
        .map(|guard| Arc::new(Mutex::new(guard)));
    let route_guard = config
        .auto_route
        .then(|| crate::tun_route_linux::LinuxTunRoutes::install(&config))
        .transpose()?
        .map(|guard| Arc::new(Mutex::new(guard)));
    let (stack, runner, udp, tcp) = StackBuilder::default()
        .enable_tcp(true)
        .enable_udp(true)
        .enable_icmp(true)
        .mtu(usize::from(config.mtu))
        .build()
        .context("create TUN userspace network stack")?;
    let runner = runner.context("TUN TCP runner was not created")?;
    let udp = udp.context("TUN UDP socket was not created")?;
    let tcp = tcp.context("TUN TCP listener was not created")?;
    tracing::info!(interface = %config.interface_name, mtu = config.mtu, "TUN inbound started");

    let (mut stack_sink, mut stack_stream) = stack.split();
    let read_device = device.clone();
    let write_device = device;
    let mut tasks = tokio::task::JoinSet::new();
    tasks.spawn(async move { runner.await.context("TUN network stack runner") });
    tasks.spawn(async move {
        let mut packet = vec![0_u8; MAX_PACKET_SIZE];
        loop {
            let length = read_device
                .recv(&mut packet)
                .await
                .context("read TUN packet")?;
            stack_sink
                .send(packet[..length].to_vec())
                .await
                .context("submit packet to TUN stack")?;
        }
    });
    tasks.spawn(async move {
        while let Some(packet) = stack_stream.next().await {
            let packet = packet.context("receive packet from TUN stack")?;
            let length = write_device
                .send(&packet)
                .await
                .context("write TUN packet")?;
            if length != packet.len() {
                bail!("short TUN packet write: {length}/{}", packet.len())
            }
        }
        bail!("TUN packet output stream closed")
    });
    tasks.spawn(run_tcp(tcp, runtime.clone(), tag.clone()));
    tasks.spawn(run_udp(
        udp,
        runtime.clone(),
        tag,
        config.udp_mapping,
        config.udp_filtering,
        config.udp_nat_max,
        config.udp_timeout,
    ));
    if !inbound.route_address_set.is_empty() || !inbound.route_exclude_address_set.is_empty() {
        tasks.spawn(run_rule_set_updater(
            config.clone(),
            static_route_addresses,
            static_route_exclude_addresses,
            inbound.route_address_set,
            inbound.route_exclude_address_set,
            rule_set_route,
            runtime,
            route_guard.as_ref().map(Arc::downgrade),
            redirect_guard.as_ref().map(Arc::downgrade),
        ));
    }

    let mut runtime_tasks = TunRuntimeTasks {
        redirect: redirect_guard,
        routes: route_guard,
        tasks,
    };
    let result = runtime_tasks
        .tasks
        .join_next()
        .await
        .context("TUN task set is empty")??;
    runtime_tasks.tasks.abort_all();
    result
}

struct TunRuntimeTasks {
    redirect: Option<Arc<Mutex<crate::tun_redirect_linux::LinuxTunRedirect>>>,
    routes: Option<Arc<Mutex<crate::tun_route_linux::LinuxTunRoutes>>>,
    tasks: tokio::task::JoinSet<Result<()>>,
}

#[allow(clippy::too_many_arguments)]
async fn run_rule_set_updater(
    base_config: TunConfig,
    static_include: Vec<IpNet>,
    static_exclude: Vec<IpNet>,
    include_tags: Vec<String>,
    exclude_tags: Vec<String>,
    route_config: RouteConfig,
    runtime: Arc<ProxyRuntime>,
    routes: Option<Weak<Mutex<crate::tun_route_linux::LinuxTunRoutes>>>,
    redirect: Option<Weak<Mutex<crate::tun_redirect_linux::LinuxTunRedirect>>>,
) -> Result<()> {
    let interval = route_config
        .rule_set
        .iter()
        .filter(|set| include_tags.contains(&set.tag) || exclude_tags.contains(&set.tag))
        .filter_map(|set| set.update_interval.as_deref())
        .map(parse_update_interval)
        .min()
        .unwrap_or_else(|| std::time::Duration::from_secs(60))
        .max(std::time::Duration::from_secs(1));
    loop {
        tokio::time::sleep(interval).await;
        let mut next = base_config.clone();
        next.route_addresses = static_include.clone();
        next.route_exclude_addresses = static_exclude.clone();
        let loaded = runtime
            .rule_set_ip_cidrs(&include_tags)
            .and_then(|include| {
                runtime
                    .rule_set_ip_cidrs(&exclude_tags)
                    .map(|exclude| (include, exclude))
            });
        let (include, exclude) = match loaded {
            Ok(value) => value,
            Err(error) => {
                tracing::warn!(%error, "failed to refresh TUN route rule-sets");
                continue;
            }
        };
        next.route_addresses.extend(include);
        next.route_exclude_addresses.extend(exclude);
        next.route_addresses.sort_by_key(ToString::to_string);
        next.route_addresses.dedup();
        next.route_exclude_addresses
            .sort_by_key(ToString::to_string);
        next.route_exclude_addresses.dedup();

        let routes = routes.as_ref().and_then(Weak::upgrade);
        let redirect = redirect.as_ref().and_then(Weak::upgrade);
        let applied = tokio::task::spawn_blocking(move || -> Result<()> {
            if let Some(routes) = routes {
                routes
                    .lock()
                    .map_err(|_| anyhow::anyhow!("TUN route lock poisoned"))?
                    .replace(&next)?;
            }
            if let Some(redirect) = redirect {
                redirect
                    .lock()
                    .map_err(|_| anyhow::anyhow!("TUN redirect lock poisoned"))?
                    .replace_route_sets(&next)?;
            }
            Ok(())
        })
        .await;
        match applied {
            Ok(Ok(())) => tracing::info!("TUN route rule-sets refreshed"),
            Ok(Err(error)) => {
                tracing::warn!(%error, "failed to apply TUN route rule-set update")
            }
            Err(error) => tracing::warn!(%error, "TUN route rule-set apply task failed"),
        }
    }
}

fn parse_update_interval(value: &str) -> std::time::Duration {
    let split = value
        .find(|character: char| !character.is_ascii_digit())
        .unwrap_or(value.len());
    let amount = value[..split].parse::<u64>().unwrap_or(60);
    match &value[split..] {
        "ms" => std::time::Duration::from_millis(amount),
        "s" | "" => std::time::Duration::from_secs(amount),
        "m" => std::time::Duration::from_secs(amount.saturating_mul(60)),
        "h" => std::time::Duration::from_secs(amount.saturating_mul(3600)),
        "d" => std::time::Duration::from_secs(amount.saturating_mul(86400)),
        _ => std::time::Duration::from_secs(60),
    }
}

impl Drop for TunRuntimeTasks {
    fn drop(&mut self) {
        // Route removal needs the interface to still exist. Task-held device
        // handles are released only after this Drop body finishes.
        drop(self.redirect.take());
        drop(self.routes.take());
        self.tasks.abort_all();
    }
}

fn build_device(config: &TunConfig) -> Result<tun_rs::AsyncDevice> {
    let mut builder = tun_rs::DeviceBuilder::new()
        .name(&config.interface_name)
        .layer(tun_rs::Layer::L3)
        .mtu(config.mtu);
    for address in &config.addresses {
        builder = match address {
            IpNet::V4(value) => builder.ipv4(value.addr(), value.prefix_len(), None),
            IpNet::V6(value) => builder.ipv6(value.addr(), value.prefix_len()),
        };
    }
    builder.build_async().context("create/configure TUN device")
}

async fn run_tcp(
    mut listener: netstack_smoltcp::TcpListener,
    runtime: Arc<ProxyRuntime>,
    inbound: String,
) -> Result<()> {
    while let Some((stream, source, destination)) = listener.next().await {
        let runtime = runtime.clone();
        let inbound = inbound.clone();
        tokio::spawn(async move {
            if let Err(error) =
                proxy::relay_tun_tcp(stream, source, destination, &inbound, &runtime).await
            {
                tracing::debug!(%error, %source, %destination, "TUN TCP flow closed");
            }
        });
    }
    bail!("TUN TCP listener closed")
}

type Datagram = (Vec<u8>, SocketAddr, SocketAddr);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum UdpMappingKey {
    Endpoint(SocketAddr),
    Address(SocketAddr, IpAddr),
    AddressAndPort(SocketAddr, SocketAddr),
}

struct UdpNatSession {
    sender: Option<mpsc::Sender<(Vec<u8>, SocketAddr)>>,
    allowed_addresses: HashSet<IpAddr>,
    allowed_endpoints: HashSet<SocketAddr>,
    last_used: std::time::Instant,
    generation: u64,
}

struct UdpNatTable {
    filtering: UdpNatBehavior,
    max_sessions: usize,
    idle_timeout: std::time::Duration,
    generation: u64,
    sessions: HashMap<UdpMappingKey, UdpNatSession>,
}

impl UdpNatTable {
    fn new(
        filtering: UdpNatBehavior,
        max_sessions: usize,
        idle_timeout: std::time::Duration,
    ) -> Self {
        Self {
            filtering,
            max_sessions,
            idle_timeout,
            generation: 0,
            sessions: HashMap::new(),
        }
    }

    fn key_for(mapping: UdpNatBehavior, source: SocketAddr, destination: SocketAddr) -> UdpMappingKey {
        match mapping {
            UdpNatBehavior::EndpointIndependent => UdpMappingKey::Endpoint(source),
            UdpNatBehavior::AddressDependent => UdpMappingKey::Address(source, destination.ip()),
            UdpNatBehavior::AddressAndPortDependent => {
                UdpMappingKey::AddressAndPort(source, destination)
            }
        }
    }


    /// Combined touch-and-fetch for the hot packet path, avoiding a second
    /// table lock and deferring expiry until the table is at capacity.
    fn touch_and_sender(&mut self, key: UdpMappingKey, destination: SocketAddr) -> Option<mpsc::Sender<(Vec<u8>, SocketAddr)>> {
        if !self.sessions.contains_key(&key) {
            self.reclaim_if_full();
        }
        self.generation = self.generation.wrapping_add(1);
        let session = self.sessions.entry(key).or_insert_with(|| UdpNatSession {
            sender: None,
            allowed_addresses: HashSet::new(),
            allowed_endpoints: HashSet::new(),
            last_used: std::time::Instant::now(),
            generation: self.generation,
        });
        session.last_used = std::time::Instant::now();
        session.generation = self.generation;
        session.allowed_addresses.insert(destination.ip());
        session.allowed_endpoints.insert(destination);
        session
            .sender
            .as_ref()
            .filter(|sender| !sender.is_closed())
            .cloned()
    }

    /// Only scan for idle entries when the table is at capacity and a new
    /// session is about to be inserted; the hot packet path otherwise skips
    /// the O(sessions) retain.
    fn reclaim_if_full(&mut self) {
        if self.sessions.len() < self.max_sessions {
            return;
        }
        let timeout = self.idle_timeout;
        let before = self.sessions.len();
        self.sessions
            .retain(|_, session| session.last_used.elapsed() < timeout);
        if self.sessions.len() == before && self.sessions.len() >= self.max_sessions {
            self.evict_lru();
        }
    }

    fn insert_sender(&mut self, key: UdpMappingKey, sender: mpsc::Sender<(Vec<u8>, SocketAddr)>) {
        if let Some(session) = self.sessions.get_mut(&key) {
            session.sender = Some(sender);
        }
    }

    fn allow_response(&mut self, key: UdpMappingKey, remote: SocketAddr) -> bool {
        self.expire();
        let Some(session) = self.sessions.get_mut(&key) else {
            return false;
        };
        let allowed = match self.filtering {
            UdpNatBehavior::EndpointIndependent => true,
            UdpNatBehavior::AddressDependent => session.allowed_addresses.contains(&remote.ip()),
            UdpNatBehavior::AddressAndPortDependent => session.allowed_endpoints.contains(&remote),
        };
        if allowed {
            self.generation = self.generation.wrapping_add(1);
            session.last_used = std::time::Instant::now();
            session.generation = self.generation;
        }
        allowed
    }

    fn expire(&mut self) {
        let timeout = self.idle_timeout;
        self.sessions
            .retain(|_, session| session.last_used.elapsed() < timeout);
    }

    fn evict_lru(&mut self) {
        if let Some(key) = self
            .sessions
            .iter()
            .min_by_key(|(_, session)| session.generation)
            .map(|(key, _)| *key)
        {
            self.sessions.remove(&key);
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_udp(
    socket: netstack_smoltcp::UdpSocket,
    runtime: Arc<ProxyRuntime>,
    inbound: String,
    mapping: UdpNatBehavior,
    filtering: UdpNatBehavior,
    max_sessions: usize,
    idle_timeout: std::time::Duration,
) -> Result<()> {
    let (mut reader, mut writer) = socket.split();
    let table = Arc::new(Mutex::new(UdpNatTable::new(
        filtering,
        max_sessions,
        idle_timeout,
    )));
    let weak_table = Arc::downgrade(&table);
    let (response_tx, mut response_rx) = mpsc::channel::<(UdpMappingKey, Datagram)>(512);
    tokio::spawn(async move {
        while let Some((key, response)) = response_rx.recv().await {
            let Some(table) = weak_table.upgrade() else {
                break;
            };
            let allowed = table
                .lock()
                .is_ok_and(|mut table| table.allow_response(key, response.1));
            if !allowed {
                continue;
            }
            if let Err(error) = writer.send(response).await {
                tracing::debug!(%error, "TUN UDP response writer closed");
                break;
            }
        }
    });
    while let Some((payload, source, destination)) = reader.next().await {
        let mapping_key = UdpNatTable::key_for(mapping, source, destination);
        let sender = {
            let mut table = table
                .lock()
                .map_err(|_| anyhow::anyhow!("TUN UDP NAT lock poisoned"))?;
            table.touch_and_sender(mapping_key, destination)
        };
        let sender = if let Some(sender) = sender {
            sender
        } else {
            let (sender, receiver) = mpsc::channel(64);
            table
                .lock()
                .map_err(|_| anyhow::anyhow!("TUN UDP NAT lock poisoned"))?
                .insert_sender(mapping_key, sender.clone());
            let runtime = runtime.clone();
            let inbound = inbound.clone();
            let responses = response_tx.clone();
            let (flow_response_tx, mut flow_response_rx) = mpsc::channel(64);
            tokio::spawn(async move {
                while let Some(response) = flow_response_rx.recv().await {
                    if responses.send((mapping_key, response)).await.is_err() {
                        break;
                    }
                }
            });
            tokio::spawn(async move {
                if let Err(error) = proxy::relay_tun_udp(
                    source,
                    &inbound,
                    &runtime,
                    receiver,
                    flow_response_tx,
                    idle_timeout,
                    mapping == UdpNatBehavior::AddressAndPortDependent,
                )
                .await
                {
                    tracing::debug!(%error, %source, %destination, "TUN UDP flow closed");
                }
            });
            sender
        };
        if sender.send((payload, destination)).await.is_err()
            && let Ok(mut table) = table.lock()
            && let Some(session) = table.sessions.get_mut(&mapping_key)
        {
            session.sender = None;
        }
    }
    bail!("TUN UDP reader closed")
}

fn parse_mac(value: &str) -> Result<[u8; 6]> {
    let bytes = value
        .split(':')
        .map(|part| u8::from_str_radix(part, 16).context("invalid MAC octet"))
        .collect::<Result<Vec<_>>>()?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("MAC address must contain six octets"))
}

async fn collect_bypass_addresses(outbounds: &[Outbound], dns: Option<&DnsConfig>) -> Vec<IpAddr> {
    let mut endpoints = outbounds
        .iter()
        .filter_map(|outbound| {
            outbound
                .server
                .as_deref()
                .map(|server| (server.to_owned(), outbound.server_port.unwrap_or(443)))
        })
        .collect::<Vec<_>>();
    if let Some(dns) = dns {
        endpoints.extend(dns.servers.iter().filter_map(|server| {
            server
                .server
                .as_deref()
                .and_then(endpoint_host)
                .map(|host| {
                    (
                        host,
                        server.server_port.unwrap_or(match server.r#type.as_str() {
                            "tls" => 853,
                            "https" => 443,
                            _ => 53,
                        }),
                    )
                })
        }));
    }
    let mut addresses = Vec::new();
    for (host, port) in endpoints {
        if let Ok(ip) = host.parse() {
            addresses.push(ip);
        } else if let Ok(resolved) = tokio::net::lookup_host((host.as_str(), port)).await {
            addresses.extend(resolved.map(|address| address.ip()));
        }
    }
    addresses.sort_unstable();
    addresses.dedup();
    addresses
}

fn endpoint_host(value: &str) -> Option<String> {
    if let Ok(url) = url::Url::parse(value) {
        return url.host_str().map(str::to_owned);
    }
    Some(value.trim_matches(['[', ']']).to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn inbound(json: &str) -> Inbound {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn parses_linux_tun_data_plane_config() {
        let config = TunConfig::from_inbound(&inbound(
            r#"{"type":"tun","tag":"tun-in","interface_name":"xhttp-test","mtu":1500,"address":["172.19.0.1/30","fdfe:dcba:9876::1/126"],"stack":"mixed"}"#,
        ))
        .unwrap();
        assert_eq!(config.interface_name, "xhttp-test");
        assert_eq!(config.mtu, 1500);
        assert_eq!(config.addresses.len(), 2);
    }

    #[test]
    fn validates_linux_auto_route_control_plane_options() {
        assert!(TunConfig::from_inbound(&inbound(r#"{"type":"tun"}"#)).is_err());
        for json in [
            r#"{"type":"tun","address":"172.19.0.1/30","auto_redirect":true}"#,
            r#"{"type":"tun","address":"172.19.0.1/30","strict_route":true}"#,
            r#"{"type":"tun","address":"172.19.0.1/30","route_address":"1.1.1.1/32"}"#,
            r#"{"type":"tun","address":"172.19.0.1/30","auto_route":true,"include_uid":1000}"#,
        ] {
            assert!(TunConfig::from_inbound(&inbound(json)).is_err(), "{json}");
        }
        let config = TunConfig::from_inbound(&inbound(
            r#"{"type":"tun","address":"172.19.0.1/30","auto_route":true,"strict_route":true,"route_address":"1.1.1.0/24","route_exclude_address":"1.1.1.1/32","exclude_uid":1000,"exclude_interface":"docker0","iproute2_table_index":22022,"iproute2_rule_index":12000}"#,
        ))
        .unwrap();
        assert!(config.auto_route);
        assert!(config.strict_route);
        assert_eq!(config.table_index, 22022);
        assert_eq!(config.rule_index, 12000);
        assert_eq!(config.exclude_uids, [1000]);

        let config = TunConfig::from_inbound(&inbound(
            r#"{"type":"tun","address":"172.19.0.1/30","auto_route":true,"auto_redirect":true,"auto_redirect_input_mark":"0x2123","auto_redirect_output_mark":"0X2124","include_uid":1000,"include_uid_range":"2000:2999","include_mac_address":"02:00:00:00:00:01"}"#,
        ))
        .unwrap();
        assert!(config.auto_redirect);
        assert_eq!(config.redirect_input_mark, 0x2123);
        assert_eq!(config.redirect_output_mark, 0x2124);
        assert_eq!(config.include_uids, [1000]);
        assert_eq!(config.include_uid_ranges, [(2000, 2999)]);
        let config = TunConfig::from_inbound(&inbound(
            r#"{"type":"tun","address":"172.19.0.1/30","udp_timeout":"45s","udp_mapping":"address_dependent","udp_filtering":"address_and_port_dependent","udp_nat_max":32}"#,
        ))
        .unwrap();
        assert_eq!(config.udp_timeout, std::time::Duration::from_secs(45));
        assert_eq!(config.udp_mapping, UdpNatBehavior::AddressDependent);
        assert_eq!(
            config.udp_filtering,
            UdpNatBehavior::AddressAndPortDependent
        );
        assert_eq!(config.udp_nat_max, 32);
        for json in [
            r#"{"type":"tun","address":"172.19.0.1/30","auto_route":true,"auto_redirect":true,"include_uid_range":"2000"}"#,
            r#"{"type":"tun","address":"172.19.0.1/30","auto_route":true,"auto_redirect":true,"include_uid_range":"3000:2000"}"#,
        ] {
            assert!(TunConfig::from_inbound(&inbound(json)).is_err(), "{json}");
        }
    }

    #[test]
    fn rejects_invalid_mtu_stack_and_multiple_ipv4_addresses() {
        for json in [
            r#"{"type":"tun","address":"172.19.0.1/30","mtu":1279}"#,
            r#"{"type":"tun","address":"172.19.0.1/30","stack":"system"}"#,
            r#"{"type":"tun","address":["172.19.0.1/30","172.20.0.1/30"]}"#,
            r#"{"type":"tun","address":"172.19.0.1/30","dns_mode":"hijack"}"#,
            r#"{"type":"tun","address":"172.19.0.1/30","udp_mapping":"cone"}"#,
            r#"{"type":"tun","address":"172.19.0.1/30","auto_redirect_nfqueue":100}"#,
        ] {
            assert!(TunConfig::from_inbound(&inbound(json)).is_err(), "{json}");
        }
    }

    #[tokio::test]
    async fn udp_nat_mapping_filtering_and_lru_are_independent() {
        let source = "172.19.0.2:53000".parse().unwrap();
        let first = "192.0.2.1:53".parse().unwrap();
        let same_address = "192.0.2.1:5353".parse().unwrap();
        let second = "198.51.100.1:53".parse().unwrap();

        assert_eq!(UdpNatTable::key_for(UdpNatBehavior::EndpointIndependent, source, first), UdpNatTable::key_for(UdpNatBehavior::EndpointIndependent, source, second));
        assert_eq!(
            UdpNatTable::key_for(UdpNatBehavior::AddressDependent, source, first),
            UdpNatTable::key_for(UdpNatBehavior::AddressDependent, source, same_address)
        );
        assert_ne!(UdpNatTable::key_for(UdpNatBehavior::AddressDependent, source, first), UdpNatTable::key_for(UdpNatBehavior::AddressDependent, source, second));

        let mut table = UdpNatTable::new(
            UdpNatBehavior::AddressAndPortDependent,
            1,
            std::time::Duration::from_secs(300),
        );
        let key = UdpNatTable::key_for(UdpNatBehavior::EndpointIndependent, source, first);
        table.touch_and_sender(key, first);
        assert!(table.allow_response(key, first));
        assert!(!table.allow_response(key, same_address));
        let (sender, mut receiver) = mpsc::channel(1);
        table.insert_sender(key, sender);

        let other_source = "172.19.0.3:53000".parse().unwrap();
        let other_key = UdpNatTable::key_for(UdpNatBehavior::EndpointIndependent, other_source, second);
        table.touch_and_sender(other_key, second);
        assert!(!table.sessions.contains_key(&key));
        assert!(receiver.recv().await.is_none());

        let mut expiring = UdpNatTable::new(
            UdpNatBehavior::EndpointIndependent,
            2,
            std::time::Duration::from_millis(1),
        );
        let expiring_key = UdpNatTable::key_for(UdpNatBehavior::EndpointIndependent, source, first);
        expiring.touch_and_sender(expiring_key, first);
        expiring.sessions.get_mut(&expiring_key).unwrap().last_used -=
            std::time::Duration::from_secs(1);
        expiring.expire();
        assert!(expiring.sessions.is_empty());
    }

    #[tokio::test]
    async fn smoltcp_udp_round_trip_preserves_flow_endpoints() {
        let (stack, _, udp, _) = StackBuilder::default()
            .enable_udp(true)
            .mtu(1500)
            .build()
            .unwrap();
        let (mut stack_sink, mut stack_stream) = stack.split();
        let (mut udp_reader, mut udp_writer) = udp.unwrap().split();
        let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 19, 0, 2)), 53000);
        let destination = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53);
        stack_sink
            .send(ipv4_udp_packet(source, destination, b"query"))
            .await
            .unwrap();
        let (payload, local, remote) = udp_reader.next().await.unwrap();
        assert_eq!(payload, b"query");
        assert_eq!(local, source);
        assert_eq!(remote, destination);

        udp_writer
            .send((b"reply".to_vec(), destination, source))
            .await
            .unwrap();
        let response = stack_stream.next().await.unwrap().unwrap();
        assert_eq!(
            &response[12..16],
            &destination
                .ip()
                .to_string()
                .parse::<Ipv4Addr>()
                .unwrap()
                .octets()
        );
        assert_eq!(
            &response[16..20],
            &source
                .ip()
                .to_string()
                .parse::<Ipv4Addr>()
                .unwrap()
                .octets()
        );
        assert_eq!(&response[28..], b"reply");
    }

    fn ipv4_udp_packet(source: SocketAddr, destination: SocketAddr, payload: &[u8]) -> Vec<u8> {
        let (SocketAddr::V4(source), SocketAddr::V4(destination)) = (source, destination) else {
            unreachable!()
        };
        let total_length = 20 + 8 + payload.len();
        let mut packet = vec![0_u8; total_length];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total_length as u16).to_be_bytes());
        packet[6..8].copy_from_slice(&0x4000_u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&source.ip().octets());
        packet[16..20].copy_from_slice(&destination.ip().octets());
        let checksum = internet_checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&checksum.to_be_bytes());
        packet[20..22].copy_from_slice(&source.port().to_be_bytes());
        packet[22..24].copy_from_slice(&destination.port().to_be_bytes());
        packet[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        packet[28..].copy_from_slice(payload);
        packet
    }

    fn internet_checksum(bytes: &[u8]) -> u16 {
        let mut sum = bytes
            .chunks_exact(2)
            .map(|word| u16::from_be_bytes([word[0], word[1]]) as u32)
            .sum::<u32>();
        while sum > u16::MAX as u32 {
            sum = (sum & u16::MAX as u32) + (sum >> 16);
        }
        !(sum as u16)
    }
}

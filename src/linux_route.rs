use std::{
    collections::HashMap,
    fs,
    net::{IpAddr, SocketAddr},
    path::Path,
    process::Command,
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};

const INTERFACE_CACHE_TTL: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LinuxMetadataScope {
    pub process: bool,
    pub user: bool,
    pub interface: bool,
    pub network: bool,
    pub mac: bool,
    pub hostname: bool,
}

impl LinuxMetadataScope {
    pub fn is_empty(self) -> bool {
        self == Self::default()
    }

    pub fn union(self, other: Self) -> Self {
        Self {
            process: self.process || other.process,
            user: self.user || other.user,
            interface: self.interface || other.interface,
            network: self.network || other.network,
            mac: self.mac || other.mac,
            hostname: self.hostname || other.hostname,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct LinuxRouteMetadata {
    pub process_name: Option<String>,
    pub process_path: Option<String>,
    pub user: Option<String>,
    pub user_id: Option<u32>,
    pub network_type: Option<String>,
    pub network_is_expensive: bool,
    pub network_is_constrained: bool,
    pub wifi_ssid: Option<String>,
    pub wifi_bssid: Option<String>,
    pub interface_addresses: HashMap<String, Vec<IpAddr>>,
    pub network_interface_addresses: HashMap<String, Vec<IpAddr>>,
    pub source_mac_address: Option<String>,
    pub source_hostname: Option<String>,
    pub default_interface_addresses: Vec<IpAddr>,
}

pub fn collect_tcp(peer: SocketAddr, proxy: SocketAddr, scope: LinuxMetadataScope) -> LinuxRouteMetadata {
    let mut metadata = LinuxRouteMetadata::default();
    if scope.interface {
        metadata.interface_addresses = all_interface_addresses_cached();
        for (interface, addresses) in &metadata.interface_addresses {
            metadata
                .network_interface_addresses
                .entry(interface_type(interface))
                .or_default()
                .extend(addresses);
        }
    }
    if (scope.process || scope.user)
        && let Some((inode, uid)) = find_socket_owner(peer, proxy)
    {
        metadata.user_id = Some(uid);
        metadata.user = user_name(uid);
        if scope.process
            && let Some(pid) = find_inode_process(inode)
        {
            metadata.process_name = fs::read_to_string(format!("/proc/{pid}/comm"))
                .ok()
                .map(|value| value.trim().to_owned())
                .filter(|value| !value.is_empty());
            metadata.process_path = fs::read_link(format!("/proc/{pid}/exe"))
                .ok()
                .map(|value| value.to_string_lossy().into_owned());
        }
    }
    if scope.network
        && let Some(interface) = default_interface_cached()
    {
        metadata.network_type = Some(interface_type(&interface));
        metadata.network_is_expensive = command_line(
            "nmcli",
            &["-g", "GENERAL.METERED", "device", "show", &interface],
        )
        .is_some_and(|value| matches!(value.as_str(), "yes" | "guess-yes"));
        metadata.default_interface_addresses = interface_addresses_cached(&interface);
        if metadata.network_type.as_deref() == Some("wifi") {
            metadata.wifi_ssid = command_line("iwgetid", &["-r"]);
            metadata.wifi_bssid =
                command_output("iw", &["dev", &interface, "link"]).and_then(|output| {
                    output.lines().find_map(|line| {
                        line.trim()
                            .strip_prefix("Connected to ")
                            .and_then(|value| value.split_whitespace().next())
                            .map(|value| value.to_ascii_lowercase())
                    })
                });
        }
    }
    if scope.mac {
        metadata.source_mac_address = arp_value(peer.ip(), 3);
    }
    if scope.hostname {
        metadata.source_hostname = hosts_name(peer.ip());
    }
    metadata
}

fn find_socket_owner(peer: SocketAddr, proxy: SocketAddr) -> Option<(u64, u32)> {
    ["/proc/net/tcp", "/proc/net/tcp6"]
        .into_iter()
        .filter_map(|path| fs::read_to_string(path).ok())
        .flat_map(|content| {
            content
                .lines()
                .skip(1)
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .find_map(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            let local_port = fields
                .get(1)?
                .rsplit_once(':')
                .and_then(|(_, port)| u16::from_str_radix(port, 16).ok())?;
            let remote_port = fields
                .get(2)?
                .rsplit_once(':')
                .and_then(|(_, port)| u16::from_str_radix(port, 16).ok())?;
            if local_port != peer.port() || remote_port != proxy.port() {
                return None;
            }
            let uid = fields.get(7)?.parse().ok()?;
            let inode = fields.get(9)?.parse().ok()?;
            Some((inode, uid))
        })
}

fn find_inode_process(inode: u64) -> Option<u32> {
    let target = format!("socket:[{inode}]");
    for entry in fs::read_dir("/proc").ok()?.flatten() {
        let file_name = entry.file_name();
        let Some(file_name) = file_name.to_str() else {
            continue;
        };
        let Ok(pid) = file_name.parse::<u32>() else {
            continue;
        };
        let Ok(descriptors) = fs::read_dir(entry.path().join("fd")) else {
            continue;
        };
        for descriptor in descriptors.flatten() {
            if fs::read_link(descriptor.path())
                .ok()
                .is_some_and(|value| value == Path::new(&target))
            {
                return Some(pid);
            }
        }
    }
    None
}

fn user_name(uid: u32) -> Option<String> {
    fs::read_to_string("/etc/passwd")
        .ok()?
        .lines()
        .find_map(|line| {
            let fields = line.split(':').collect::<Vec<_>>();
            (fields.get(2)?.parse::<u32>().ok()? == uid).then(|| fields[0].to_owned())
        })
}

pub fn default_interface() -> Option<String> {
    fs::read_to_string("/proc/net/route")
        .ok()?
        .lines()
        .skip(1)
        .filter_map(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            if fields.get(1)? != &"00000000" {
                return None;
            }
            let metric = fields.get(6)?.parse::<u32>().ok()?;
            Some((metric, fields[0].to_owned()))
        })
        .min_by_key(|(metric, _)| *metric)
        .map(|(_, interface)| interface)
}

fn interface_type(interface: &str) -> String {
    if interface == "lo" {
        "loopback".into()
    } else if Path::new(&format!("/sys/class/net/{interface}/wireless")).exists() {
        "wifi".into()
    } else if interface.starts_with("wwan") || interface.starts_with("rmnet") {
        "cellular".into()
    } else {
        "ethernet".into()
    }
}

fn interface_addresses_cached(interface: &str) -> Vec<IpAddr> {
    all_interface_addresses_cached()
        .get(&interface.to_ascii_lowercase())
        .cloned()
        .unwrap_or_default()
}

struct Cached<T> {
    value: T,
    captured: Instant,
}

type InterfaceCache = Mutex<Option<Cached<HashMap<String, Vec<IpAddr>>>>>;
type DefaultInterfaceCache = Mutex<Option<Cached<Option<String>>>>;

fn all_interface_addresses_cached() -> HashMap<String, Vec<IpAddr>> {
    static CACHE: OnceLock<InterfaceCache> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(None));
    let mut guard = cache.lock().expect("interface cache lock poisoned");
    if let Some(cached) = guard.as_ref()
        && cached.captured.elapsed() < INTERFACE_CACHE_TTL
    {
        return cached.value.clone();
    }
    let value = all_interface_addresses();
    *guard = Some(Cached {
        value: value.clone(),
        captured: Instant::now(),
    });
    value
}

fn default_interface_cached() -> Option<String> {
    static CACHE: OnceLock<DefaultInterfaceCache> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(None));
    let mut guard = cache.lock().expect("default interface cache lock poisoned");
    if let Some(cached) = guard.as_ref()
        && cached.captured.elapsed() < INTERFACE_CACHE_TTL
    {
        return cached.value.clone();
    }
    let value = default_interface();
    *guard = Some(Cached {
        value: value.clone(),
        captured: Instant::now(),
    });
    value
}

fn all_interface_addresses() -> HashMap<String, Vec<IpAddr>> {
    let mut result: HashMap<String, Vec<IpAddr>> = HashMap::new();
    let Some(output) = command_output("ip", &["-o", "addr", "show"]) else {
        return result;
    };
    for line in output.lines() {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        let Some(interface) = fields.get(1).map(|value| value.trim_end_matches(':')) else {
            continue;
        };
        let Some(address) = fields.iter().find_map(|field| {
            field
                .split_once('/')
                .and_then(|(address, _)| address.parse::<IpAddr>().ok())
        }) else {
            continue;
        };
        result
            .entry(interface.to_ascii_lowercase())
            .or_default()
            .push(address);
    }
    result
}

fn arp_value(ip: IpAddr, field: usize) -> Option<String> {
    fs::read_to_string("/proc/net/arp")
        .ok()?
        .lines()
        .skip(1)
        .find_map(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            (fields.first()?.parse::<IpAddr>().ok()? == ip)
                .then(|| fields.get(field).map(|value| value.to_ascii_lowercase()))
                .flatten()
        })
}

fn hosts_name(ip: IpAddr) -> Option<String> {
    fs::read_to_string("/etc/hosts")
        .ok()?
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .find_map(|line| {
            let mut fields = line.split_whitespace();
            (fields.next()?.parse::<IpAddr>().ok()? == ip)
                .then(|| fields.next().map(str::to_owned))
                .flatten()
        })
}

fn command_line(program: &str, arguments: &[&str]) -> Option<String> {
    command_output(program, arguments)
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn command_output(program: &str, arguments: &[&str]) -> Option<String> {
    let output = Command::new(program).args(arguments).output().ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_is_empty_only_when_all_flags_are_clear() {
        assert!(LinuxMetadataScope::default().is_empty());
        assert!(!LinuxMetadataScope {
            process: true,
            ..Default::default()
        }
        .is_empty());
        assert!(!LinuxMetadataScope {
            hostname: true,
            ..Default::default()
        }
        .is_empty());
    }

    #[test]
    fn scope_union_or_combines_flags() {
        let process = LinuxMetadataScope {
            process: true,
            ..Default::default()
        };
        let network = LinuxMetadataScope {
            network: true,
            ..Default::default()
        };
        let combined = process.union(network);
        assert!(combined.process);
        assert!(combined.network);
        assert!(!combined.user);
        assert!(!combined.interface);
        assert!(!combined.mac);
        assert!(!combined.hostname);

        let mac_hostname = LinuxMetadataScope {
            mac: true,
            hostname: true,
            ..Default::default()
        };
        let merged = combined.union(mac_hostname);
        assert!(merged.process && merged.network && merged.mac && merged.hostname);
        assert!(!merged.user);

        let empty = LinuxMetadataScope::default();
        assert_eq!(combined.union(empty), combined);
        assert_eq!(empty.union(mac_hostname), mac_hostname);
    }

    #[test]
    fn scope_union_is_idempotent() {
        let scope = LinuxMetadataScope {
            process: true,
            user: true,
            interface: true,
            network: true,
            mac: true,
            hostname: true,
        };
        assert_eq!(scope.union(scope), scope);
    }
}

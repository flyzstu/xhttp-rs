use std::{
    collections::{HashMap, HashSet},
    fs,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::Path,
    process::Command,
    sync::{LazyLock, Mutex, OnceLock},
    time::{Duration, Instant},
};

const INTERFACE_CACHE_TTL: Duration = Duration::from_secs(5);
const SOCKET_CACHE_TTL: Duration = Duration::from_millis(500);

/// Decode a `/proc/net/tcp(6)` hex endpoint (e.g. `0100007F:1F90` or its
/// IPv6 equivalent) into a `SocketAddr`.
fn parse_proc_endpoint(value: &str, ipv6: bool) -> Option<SocketAddr> {
    let (address, port) = value.rsplit_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    let ip = if ipv6 {
        let octets = (0..4)
            .map(|word| -> Option<[u8; 4]> {
                Some(
                    u32::from_str_radix(address.get(word * 8..word * 8 + 8)?, 16)
                        .ok()?
                        .to_ne_bytes(),
                )
            })
            .collect::<Option<Vec<_>>>()?
            .concat();
        IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(octets.as_slice()).ok()?,
        ))
    } else {
        // IPv4 addresses in /proc/net/tcp are little-endian.
        IpAddr::V4(Ipv4Addr::from(
            u32::from_str_radix(address, 16).ok()?.swap_bytes(),
        ))
    };
    Some(SocketAddr::new(ip, port))
}

/// Compare one `/proc/net/tcp(6)` endpoint with a flow endpoint. A wildcard
/// address is accepted for a local endpoint captured before the socket was
/// fully bound; remote endpoints must match exactly.
fn endpoint_matches(entry: SocketAddr, expected: SocketAddr, local: bool) -> bool {
    if entry.port() != expected.port() {
        return false;
    }
    let entry_ip = entry.ip().to_canonical();
    let expected_ip = expected.ip().to_canonical();
    entry_ip == expected_ip || (local && entry_ip.is_unspecified())
}

/// Match a `/proc/net/tcp(6)` entry against the flow's full 4-tuple. Both
/// endpoints' addresses and ports must match, not just the ports. Both
/// orientations are accepted because callers historically passed the peer and
/// proxy sockets in either order.
fn socket_matches_flow(
    entry_local: SocketAddr,
    entry_remote: SocketAddr,
    peer: SocketAddr,
    proxy: SocketAddr,
) -> bool {
    (endpoint_matches(entry_local, proxy, true) && endpoint_matches(entry_remote, peer, false))
        || (endpoint_matches(entry_local, peer, true)
            && endpoint_matches(entry_remote, proxy, false))
}

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

pub fn collect_tcp(
    peer: SocketAddr,
    proxy: SocketAddr,
    scope: LinuxMetadataScope,
) -> LinuxRouteMetadata {
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

#[derive(Clone)]
/// A single parsed `/proc/net/tcp(6)` entry: the inode, uid, and the entry's
/// full local/remote 4-tuple.
struct SocketEntry {
    inode: u64,
    uid: u32,
    local: SocketAddr,
    remote: SocketAddr,
}

fn parse_proc_socket_table(ipv6: bool) -> Vec<SocketEntry> {
    let path = if ipv6 {
        "/proc/net/tcp6"
    } else {
        "/proc/net/tcp"
    };
    let Ok(content) = fs::read_to_string(path) else {
        return Vec::new();
    };
    content
        .lines()
        .skip(1)
        .filter_map(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            let local = parse_proc_endpoint(fields.get(1)?, ipv6)?;
            let remote = parse_proc_endpoint(fields.get(2)?, ipv6)?;
            Some(SocketEntry {
                inode: fields.get(9)?.parse().ok()?,
                uid: fields.get(7)?.parse().ok()?,
                local,
                remote,
            })
        })
        .collect()
}

/// Find the socket entry whose full 4-tuple matches this flow. Falls back to
/// a port-only match when the addresses cannot be parsed from the proc table.
fn find_socket_entry(peer: SocketAddr, proxy: SocketAddr) -> Option<SocketEntry> {
    let entries = [
        parse_proc_socket_table(false),
        parse_proc_socket_table(true),
    ]
    .concat();
    entries
        .iter()
        .find(|entry| socket_matches_flow(entry.local, entry.remote, peer, proxy))
        .or_else(|| {
            entries.iter().find(|entry| {
                (entry.local.port() == peer.port() && entry.remote.port() == proxy.port())
                    || (entry.local.port() == proxy.port() && entry.remote.port() == peer.port())
            })
        })
        .cloned()
}

fn find_socket_owner(peer: SocketAddr, proxy: SocketAddr) -> Option<(u64, u32)> {
    let entry = find_socket_entry(peer, proxy)?;
    Some((entry.inode, entry.uid))
}

type InodeProcessCache = Mutex<Option<Cached<HashMap<u32, HashSet<u64>>>>>;
/// Cached per-process set of socket inodes. Each refresh scans `/proc/<pid>/fd`
/// once; lookups within the TTL skip all rescanning.
static INODE_PROCESS_CACHE: LazyLock<InodeProcessCache> = LazyLock::new(|| Mutex::new(None));

fn process_inode_map(pid: u32) -> Option<HashSet<u64>> {
    let guard = INODE_PROCESS_CACHE
        .lock()
        .expect("inode process cache lock poisoned");
    if guard
        .as_ref()
        .is_some_and(|cached| cached.captured.elapsed() < SOCKET_CACHE_TTL)
    {
        let result = guard.as_ref()?.value.get(&pid).cloned();
        if result.is_some() {
            return result;
        }
    }
    drop(guard);
    let inodes = fs::read_dir(format!("/proc/{pid}/fd"))
        .ok()
        .map(|descriptors| {
            descriptors
                .flatten()
                .filter_map(|descriptor| {
                    let target = fs::read_link(descriptor.path()).ok()?;
                    let name = target.to_str()?;
                    name.strip_prefix("socket:[")?
                        .strip_suffix(']')?
                        .parse::<u64>()
                        .ok()
                })
                .collect::<HashSet<_>>()
        })?;
    let mut guard = INODE_PROCESS_CACHE
        .lock()
        .expect("inode process cache lock poisoned");
    guard
        .get_or_insert_with(|| Cached {
            value: HashMap::new(),
            captured: Instant::now(),
        })
        .value
        .insert(pid, inodes.clone());
    Some(inodes)
}

fn find_inode_process(inode: u64) -> Option<u32> {
    let guard = INODE_PROCESS_CACHE
        .lock()
        .expect("inode process cache lock poisoned");
    if let Some(cached) = guard.as_ref()
        && cached.captured.elapsed() < SOCKET_CACHE_TTL
        && let Some(pid) = cached
            .value
            .iter()
            .find_map(|(pid, inodes)| inodes.contains(&inode).then_some(*pid))
    {
        return Some(pid);
    }
    drop(guard);

    for entry in fs::read_dir("/proc").ok()?.flatten() {
        let file_name = entry.file_name();
        let Some(file_name) = file_name.to_str() else {
            continue;
        };
        let Ok(pid) = file_name.parse::<u32>() else {
            continue;
        };
        if let Some(inodes) = process_inode_map(pid)
            && inodes.contains(&inode)
        {
            return Some(pid);
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
        assert!(
            !LinuxMetadataScope {
                process: true,
                ..Default::default()
            }
            .is_empty()
        );
        assert!(
            !LinuxMetadataScope {
                hostname: true,
                ..Default::default()
            }
            .is_empty()
        );
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

    #[test]
    fn parse_proc_endpoint_decodes_little_endian_addresses() {
        assert_eq!(
            parse_proc_endpoint("0100007F:1F90", false),
            Some("127.0.0.1:8080".parse().unwrap())
        );
        assert_eq!(
            parse_proc_endpoint("00000000000000000000000001000000:01BB", true),
            Some("[::1]:443".parse().unwrap())
        );
    }

    #[test]
    fn socket_match_requires_both_addresses_and_ports() {
        let local: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let remote: SocketAddr = "192.0.2.10:50000".parse().unwrap();
        let wrong_address: SocketAddr = "192.0.2.11:50000".parse().unwrap();
        let wrong_port: SocketAddr = "192.0.2.10:50001".parse().unwrap();

        assert!(socket_matches_flow(local, remote, remote, local));
        assert!(!socket_matches_flow(local, remote, wrong_address, local));
        assert!(!socket_matches_flow(local, remote, wrong_port, local));
        // Both peer/proxy orderings are accepted, so the reverse of a valid
        // flow is still a match — not a mismatch.
        assert!(socket_matches_flow(local, remote, local, remote));
    }
}

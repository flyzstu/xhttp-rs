use crate::tun::TunConfig;
use anyhow::{Context, Result, bail};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::fd::AsRawFd,
    path::PathBuf,
    process::{Command, Stdio},
};

pub(crate) struct LinuxTunRedirect {
    table: String,
    table_installed: bool,
    sysctls: Vec<(PathBuf, String)>,
    docker_rules: Vec<DockerRule>,
    lock: File,
}

#[derive(Clone)]
struct DockerRule {
    program: &'static str,
    arguments: Vec<String>,
}

impl LinuxTunRedirect {
    pub(crate) fn install(config: &TunConfig) -> Result<Self> {
        let table = table_name(&config.interface_name)?;
        let lock_path = format!("/run/xhttp-rs-{table}.lock");
        let mut lock = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)
            .with_context(|| format!("open auto_redirect lock {lock_path}"))?;
        let result = unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result != 0 {
            return Err(std::io::Error::last_os_error())
                .context("another xhttp-rs auto_redirect instance owns this TUN interface");
        }
        let stale_sysctls = read_sysctl_state(&mut lock)?;
        let mut guard = Self {
            table,
            table_installed: false,
            sysctls: stale_sysctls,
            docker_rules: Vec::new(),
            lock,
        };

        // A deterministic table name plus an exclusive process lock lets a new
        // instance remove a table left behind by SIGKILL without touching a
        // concurrently running instance.
        let _ = delete_nft_table(&guard.table);
        if config
            .addresses
            .iter()
            .any(|address| address.addr().is_ipv4())
        {
            guard.enable_sysctl("/proc/sys/net/ipv4/ip_forward")?;
        }
        if config
            .addresses
            .iter()
            .any(|address| address.addr().is_ipv6())
        {
            guard.enable_sysctl("/proc/sys/net/ipv6/conf/all/forwarding")?;
        }
        guard.persist_sysctl_state()?;
        run_nft_script(&build_nft_script(config, &guard.table)?)?;
        guard.table_installed = true;
        guard.install_docker_compatibility(config);
        tracing::info!(
            table = %guard.table,
            input_mark = format_args!("0x{:x}", config.redirect_input_mark),
            output_mark = format_args!("0x{:x}", config.redirect_output_mark),
            "Linux TUN nftables auto_redirect installed"
        );
        Ok(guard)
    }

    pub(crate) fn replace_route_sets(&self, config: &TunConfig) -> Result<()> {
        let mut lines = Vec::new();
        replace_address_set(
            &mut lines,
            &self.table,
            "route4",
            config
                .route_addresses
                .iter()
                .filter(|value| value.addr().is_ipv4())
                .map(ToString::to_string),
        );
        replace_address_set(
            &mut lines,
            &self.table,
            "route6",
            config
                .route_addresses
                .iter()
                .filter(|value| value.addr().is_ipv6())
                .map(ToString::to_string),
        );
        replace_address_set(
            &mut lines,
            &self.table,
            "exclude4",
            config
                .route_exclude_addresses
                .iter()
                .filter(|value| value.addr().is_ipv4())
                .map(ToString::to_string),
        );
        replace_address_set(
            &mut lines,
            &self.table,
            "exclude6",
            config
                .route_exclude_addresses
                .iter()
                .filter(|value| value.addr().is_ipv6())
                .map(ToString::to_string),
        );
        run_nft_script(&(lines.join("\n") + "\n"))
    }

    fn enable_sysctl(&mut self, path: &str) -> Result<()> {
        let path = PathBuf::from(path);
        let current =
            fs::read_to_string(&path).with_context(|| format!("read sysctl {}", path.display()))?;
        let current = current.trim().to_owned();
        if current != "1" {
            fs::write(&path, "1\n").with_context(|| format!("enable sysctl {}", path.display()))?;
            if !self.sysctls.iter().any(|(saved, _)| saved == &path) {
                self.sysctls.push((path, current));
            }
        }
        Ok(())
    }

    fn persist_sysctl_state(&mut self) -> Result<()> {
        self.lock
            .set_len(0)
            .context("truncate auto_redirect state")?;
        self.lock
            .seek(SeekFrom::Start(0))
            .context("seek auto_redirect state")?;
        for (path, previous) in &self.sysctls {
            writeln!(self.lock, "{}={previous}", path.display())
                .context("write auto_redirect state")?;
        }
        self.lock.sync_data().context("sync auto_redirect state")
    }

    fn install_docker_compatibility(&mut self, config: &TunConfig) {
        for (program, enabled) in [
            (
                "iptables",
                config.addresses.iter().any(|value| value.addr().is_ipv4()),
            ),
            (
                "ip6tables",
                config.addresses.iter().any(|value| value.addr().is_ipv6()),
            ),
        ] {
            if !enabled || !command_success(program, &["-w", "-S", "DOCKER-USER"]) {
                continue;
            }
            for direction in ["-i", "-o"] {
                let comment = format!("xhttp-rs:{}:{direction}", config.interface_name);
                let arguments = vec![
                    "-w".into(),
                    "DOCKER-USER".into(),
                    direction.into(),
                    config.interface_name.clone(),
                    "-m".into(),
                    "comment".into(),
                    "--comment".into(),
                    comment,
                    "-j".into(),
                    "ACCEPT".into(),
                ];
                let mut insert = vec!["-I".into()];
                insert.extend(arguments.clone());
                if command_owned_success(program, &insert) {
                    self.docker_rules.push(DockerRule { program, arguments });
                }
            }
        }
    }
}

impl Drop for LinuxTunRedirect {
    fn drop(&mut self) {
        for rule in self.docker_rules.drain(..).rev() {
            let mut arguments = vec!["-D".into()];
            arguments.extend(rule.arguments);
            if !command_owned_success(rule.program, &arguments) {
                tracing::warn!(
                    program = rule.program,
                    "failed to remove Docker TUN accept rule"
                );
            }
        }
        if self.table_installed
            && let Err(error) = delete_nft_table(&self.table)
        {
            tracing::warn!(%error, table = %self.table, "failed to remove nftables auto_redirect table");
        }
        let mut restore_failed = false;
        for (path, previous) in self.sysctls.drain(..).rev() {
            // Do not undo an administrator's concurrent change away from the
            // value installed by this process.
            if fs::read_to_string(&path)
                .ok()
                .is_some_and(|value| value.trim() == "1")
                && let Err(error) = fs::write(&path, format!("{previous}\n"))
            {
                restore_failed = true;
                tracing::warn!(%error, path = %path.display(), "failed to restore forwarding sysctl");
            }
        }
        if !restore_failed {
            let _ = self.lock.set_len(0);
        }
    }
}

fn read_sysctl_state(lock: &mut File) -> Result<Vec<(PathBuf, String)>> {
    lock.seek(SeekFrom::Start(0))
        .context("seek auto_redirect state")?;
    let mut state = String::new();
    lock.read_to_string(&mut state)
        .context("read auto_redirect state")?;
    Ok(state
        .lines()
        .filter_map(|line| line.split_once('='))
        .filter(|(path, value)| {
            matches!(
                *path,
                "/proc/sys/net/ipv4/ip_forward" | "/proc/sys/net/ipv6/conf/all/forwarding"
            ) && matches!(*value, "0" | "1")
        })
        .map(|(path, value)| (PathBuf::from(path), value.to_owned()))
        .collect())
}

fn table_name(interface: &str) -> Result<String> {
    if interface.is_empty()
        || !interface
            .bytes()
            .all(|value| value.is_ascii_alphanumeric() || matches!(value, b'_' | b'-' | b'.'))
    {
        bail!("TUN interface_name contains characters unsafe for nftables")
    }
    Ok(format!("xhttp_{}", interface.replace(['-', '.'], "_")))
}

fn build_nft_script(config: &TunConfig, table: &str) -> Result<String> {
    let mut lines = vec![format!("add table inet {table}")];
    let local = local_prefixes(&config.interface_name);
    add_address_set(
        &mut lines,
        table,
        "local4",
        "ipv4_addr",
        local.iter().filter(|value| value.contains('.')).cloned(),
    );
    add_address_set(
        &mut lines,
        table,
        "local6",
        "ipv6_addr",
        local.iter().filter(|value| value.contains(':')).cloned(),
    );
    add_address_set(
        &mut lines,
        table,
        "route4",
        "ipv4_addr",
        config
            .route_addresses
            .iter()
            .filter(|value| value.addr().is_ipv4())
            .map(ToString::to_string),
    );
    add_address_set(
        &mut lines,
        table,
        "route6",
        "ipv6_addr",
        config
            .route_addresses
            .iter()
            .filter(|value| value.addr().is_ipv6())
            .map(ToString::to_string),
    );
    add_address_set(
        &mut lines,
        table,
        "exclude4",
        "ipv4_addr",
        config
            .route_exclude_addresses
            .iter()
            .filter(|value| value.addr().is_ipv4())
            .map(ToString::to_string),
    );
    add_address_set(
        &mut lines,
        table,
        "exclude6",
        "ipv6_addr",
        config
            .route_exclude_addresses
            .iter()
            .filter(|value| value.addr().is_ipv6())
            .map(ToString::to_string),
    );
    add_address_set(
        &mut lines,
        table,
        "bypass4",
        "ipv4_addr",
        config
            .bypass_addresses
            .iter()
            .filter(|value| value.is_ipv4())
            .map(ToString::to_string),
    );
    add_address_set(
        &mut lines,
        table,
        "bypass6",
        "ipv6_addr",
        config
            .bypass_addresses
            .iter()
            .filter(|value| value.is_ipv6())
            .map(ToString::to_string),
    );

    lines.push(format!(
        "add chain inet {table} prerouting {{ type filter hook prerouting priority mangle; policy accept; }}"
    ));
    lines.push(format!(
        "add chain inet {table} output {{ type route hook output priority mangle; policy accept; }}"
    ));
    let interface = nft_string(&config.interface_name);
    lines.push(format!(
        "add rule inet {table} prerouting iifname {interface} return"
    ));
    add_common_exclusions(&mut lines, table, "prerouting", config, false);
    lines.push(format!(
        "add rule inet {table} prerouting meta l4proto {{ tcp, udp, icmp, ipv6-icmp }} counter ct mark set 0x{:x} meta mark set ct mark",
        config.redirect_input_mark
    ));
    lines.push(format!(
        "add rule inet {table} output meta mark 0x{:x} return",
        config.redirect_output_mark
    ));
    lines.push(format!(
        "add rule inet {table} output oifname {interface} return"
    ));
    add_common_exclusions(&mut lines, table, "output", config, true);
    lines.push(format!(
        "add rule inet {table} output meta l4proto {{ tcp, udp, icmp, ipv6-icmp }} counter ct mark set 0x{:x} meta mark set ct mark",
        config.redirect_input_mark
    ));
    Ok(lines.join("\n") + "\n")
}

fn add_common_exclusions(
    lines: &mut Vec<String>,
    table: &str,
    chain: &str,
    config: &TunConfig,
    output: bool,
) {
    if output {
        if !config.include_uids.is_empty() || !config.include_uid_ranges.is_empty() {
            lines.push(format!(
                "add rule inet {table} {chain} meta skuid != {{ {} }} return",
                join_uids(&config.include_uids, &config.include_uid_ranges)
            ));
        }
        if !config.exclude_uids.is_empty() || !config.exclude_uid_ranges.is_empty() {
            lines.push(format!(
                "add rule inet {table} {chain} meta skuid {{ {} }} return",
                join_uids(&config.exclude_uids, &config.exclude_uid_ranges)
            ));
        }
    } else {
        if !config.include_interfaces.is_empty() {
            lines.push(format!(
                "add rule inet {table} {chain} iifname != {{ {} }} return",
                join_strings(&config.include_interfaces)
            ));
        }
        if !config.exclude_interfaces.is_empty() {
            lines.push(format!(
                "add rule inet {table} {chain} iifname {{ {} }} return",
                join_strings(&config.exclude_interfaces)
            ));
        }
        if !config.include_macs.is_empty() {
            lines.push(format!(
                "add rule inet {table} {chain} meta iiftype != ether return"
            ));
            lines.push(format!(
                "add rule inet {table} {chain} ether saddr != {{ {} }} return",
                config.include_macs.join(", ")
            ));
        }
        if !config.exclude_macs.is_empty() {
            lines.push(format!(
                "add rule inet {table} {chain} ether saddr {{ {} }} return",
                config.exclude_macs.join(", ")
            ));
        }
    }
    for (family, prefix) in [("ip", "4"), ("ip6", "6")] {
        lines.push(format!(
            "add rule inet {table} {chain} {family} daddr @local{prefix} return"
        ));
        lines.push(format!(
            "add rule inet {table} {chain} {family} daddr @bypass{prefix} return"
        ));
        if config.route_include_active {
            lines.push(format!(
                "add rule inet {table} {chain} {family} daddr != @route{prefix} return"
            ));
        }
        if config.route_exclude_active {
            lines.push(format!(
                "add rule inet {table} {chain} {family} daddr @exclude{prefix} return"
            ));
        }
    }
}

fn add_address_set<I>(lines: &mut Vec<String>, table: &str, name: &str, data_type: &str, values: I)
where
    I: IntoIterator<Item = String>,
{
    let values = values.into_iter().collect::<Vec<_>>();
    lines.push(format!(
        "add set inet {table} {name} {{ type {data_type}; flags interval; auto-merge; }}"
    ));
    if !values.is_empty() {
        lines.push(format!(
            "add element inet {table} {name} {{ {} }}",
            values.join(", ")
        ));
    }
}

fn replace_address_set<I>(lines: &mut Vec<String>, table: &str, name: &str, values: I)
where
    I: IntoIterator<Item = String>,
{
    lines.push(format!("flush set inet {table} {name}"));
    let values = values.into_iter().collect::<Vec<_>>();
    if !values.is_empty() {
        lines.push(format!(
            "add element inet {table} {name} {{ {} }}",
            values.join(", ")
        ));
    }
}

fn local_prefixes(tun_interface: &str) -> Vec<String> {
    let Ok(output) = Command::new("ip").args(["-o", "addr", "show"]).output() else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            if fields
                .get(1)
                .is_some_and(|value| value.trim_end_matches(':') == tun_interface)
            {
                return None;
            }
            fields
                .iter()
                .find(|value| value.contains('/') && (value.contains('.') || value.contains(':')))
                .map(|value| (*value).to_owned())
        })
        .collect()
}

fn nft_string(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\\\""))
}

fn join_strings(values: &[String]) -> String {
    values
        .iter()
        .map(|value| nft_string(value))
        .collect::<Vec<_>>()
        .join(", ")
}

fn join_uids(values: &[u32], ranges: &[(u32, u32)]) -> String {
    values
        .iter()
        .map(u32::to_string)
        .chain(ranges.iter().map(|(start, end)| format!("{start}-{end}")))
        .collect::<Vec<_>>()
        .join(", ")
}

fn run_nft_script(script: &str) -> Result<()> {
    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("start nftables")?;
    child
        .stdin
        .take()
        .context("open nftables stdin")?
        .write_all(script.as_bytes())
        .context("write nftables transaction")?;
    let output = child.wait_with_output().context("wait for nftables")?;
    if !output.status.success() {
        bail!(
            "nftables transaction failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )
    }
    Ok(())
}

fn delete_nft_table(table: &str) -> Result<()> {
    let output = Command::new("nft")
        .args(["delete", "table", "inet", table])
        .output()
        .context("delete nftables table")?;
    if !output.status.success() {
        let error = String::from_utf8_lossy(&output.stderr);
        if !error.contains("No such file or directory") {
            bail!("delete nftables table failed: {}", error.trim())
        }
    }
    Ok(())
}

fn command_success(program: &str, arguments: &[&str]) -> bool {
    Command::new(program)
        .args(arguments)
        .output()
        .is_ok_and(|output| output.status.success())
}

fn command_owned_success(program: &str, arguments: &[String]) -> bool {
    Command::new(program)
        .args(arguments)
        .output()
        .is_ok_and(|output| output.status.success())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipnet::IpNet;

    fn config() -> TunConfig {
        TunConfig {
            interface_name: "xhttp0".into(),
            mtu: 1500,
            addresses: vec!["172.19.0.1/30".parse().unwrap()],
            stack: "smoltcp".into(),
            auto_route: true,
            auto_redirect: true,
            strict_route: true,
            route_addresses: vec!["0.0.0.0/0".parse::<IpNet>().unwrap()],
            route_exclude_addresses: vec!["10.0.0.0/8".parse().unwrap()],
            route_include_active: true,
            route_exclude_active: true,
            include_interfaces: vec!["lan0".into()],
            exclude_interfaces: Vec::new(),
            include_uids: vec![1000],
            exclude_uids: Vec::new(),
            include_uid_ranges: vec![(2000, 2999)],
            exclude_uid_ranges: Vec::new(),
            table_index: 22022,
            rule_index: 12000,
            redirect_input_mark: 0x2023,
            redirect_output_mark: 0x2024,
            include_macs: vec!["02:00:00:00:00:02".into()],
            exclude_macs: Vec::new(),
            bypass_addresses: vec!["192.0.2.1".parse().unwrap()],
            udp_timeout: std::time::Duration::from_secs(300),
            udp_mapping: crate::tun::UdpNatBehavior::EndpointIndependent,
            udp_filtering: crate::tun::UdpNatBehavior::EndpointIndependent,
            udp_nat_max: 16_384,
        }
    }

    #[test]
    fn nft_plan_contains_router_filters_marks_and_bypass() {
        let script = build_nft_script(&config(), "xhttp_xhttp0").unwrap();
        assert!(script.contains("type filter hook prerouting priority mangle"));
        assert!(script.contains("type route hook output priority mangle"));
        assert!(script.contains("iifname != { \"lan0\" } return"));
        assert!(script.contains("ether saddr != { 02:00:00:00:00:02 } return"));
        assert!(script.contains("meta skuid != { 1000, 2000-2999 } return"));
        assert!(script.contains("ip daddr @bypass4 return"));
        assert!(script.contains("ip6 daddr != @route6 return"));
        assert!(script.contains("ct mark set 0x2023 meta mark set ct mark"));
        assert!(script.contains("meta mark 0x2024 return"));
    }

    #[test]
    fn nft_table_name_rejects_parser_metacharacters() {
        assert!(table_name("xhttp0").is_ok());
        assert!(table_name("bad\";flush ruleset").is_err());
    }
}

use crate::tun::TunConfig;
use anyhow::{Context, Result, bail};
use ipnet::IpNet;
use std::process::Command;

#[derive(Debug, Clone, PartialEq, Eq)]
struct IpAction {
    family: &'static str,
    add: Vec<String>,
    delete: Vec<String>,
}

impl IpAction {
    fn route(family: &'static str, prefix: IpNet, interface: &str, table: u32) -> Self {
        let tail = vec![
            prefix.to_string(),
            "dev".into(),
            interface.into(),
            "table".into(),
            table.to_string(),
        ];
        Self::new(family, "route", tail)
    }

    fn rule(family: &'static str, priority: u32, selectors: Vec<String>) -> Self {
        let mut tail = vec!["priority".into(), priority.to_string()];
        tail.extend(selectors);
        Self::new(family, "rule", tail)
    }

    fn new(family: &'static str, object: &str, tail: Vec<String>) -> Self {
        let mut add = vec![object.into(), "add".into()];
        add.extend(tail.clone());
        let mut delete = vec![object.into(), "del".into()];
        delete.extend(tail);
        Self {
            family,
            add,
            delete,
        }
    }
}

pub(crate) struct LinuxTunRoutes {
    installed: Vec<IpAction>,
}

impl LinuxTunRoutes {
    pub(crate) fn install(config: &TunConfig) -> Result<Self> {
        let actions = build_actions(config)?;
        let mut guard = Self {
            installed: Vec::with_capacity(actions.len()),
        };
        // The TUN file descriptor disappears automatically after SIGKILL, but
        // policy rules survive. Remove only this deterministic plan before
        // reinstalling it; the auto_redirect process lock prevents a live
        // owner of the same interface from reaching this point.
        for action in actions.iter().rev() {
            run_ip_delete(action.family, &action.delete).with_context(|| {
                format!(
                    "remove stale TUN route action: ip {} {}",
                    action.family,
                    action.delete.join(" ")
                )
            })?;
        }
        for action in actions {
            run_ip(action.family, &action.add).with_context(|| {
                format!(
                    "install TUN route action: ip {} {}",
                    action.family,
                    action.add.join(" ")
                )
            })?;
            guard.installed.push(action);
        }
        tracing::info!(
            table = config.table_index,
            rule_priority = config.rule_index,
            actions = guard.installed.len(),
            "Linux TUN automatic routing installed"
        );
        Ok(guard)
    }

    pub(crate) fn replace(&mut self, config: &TunConfig) -> Result<()> {
        let next = build_actions(config)?;
        let removed = self
            .installed
            .iter()
            .filter(|action| !next.contains(action))
            .cloned()
            .collect::<Vec<_>>();
        let added = next
            .iter()
            .filter(|action| !self.installed.contains(action))
            .cloned()
            .collect::<Vec<_>>();

        for action in removed.iter().rev() {
            run_ip_delete(action.family, &action.delete)?;
        }
        let mut installed_added: Vec<IpAction> = Vec::new();
        for action in &added {
            if let Err(error) = run_ip(action.family, &action.add) {
                for installed in installed_added.iter().rev() {
                    let _ = run_ip_delete(installed.family, &installed.delete);
                }
                for previous in &removed {
                    let _ = run_ip(previous.family, &previous.add);
                }
                return Err(error).context("replace TUN rule-set routes");
            }
            installed_added.push(action.clone());
        }
        self.installed = next;
        Ok(())
    }
}

impl Drop for LinuxTunRoutes {
    fn drop(&mut self) {
        for action in self.installed.drain(..).rev() {
            if let Err(error) = run_ip_delete(action.family, &action.delete) {
                tracing::warn!(
                    %error,
                    command = %format!("ip {} {}", action.family, action.delete.join(" ")),
                    "failed to remove Linux TUN route action"
                );
            }
        }
    }
}

fn run_ip(family: &str, arguments: &[String]) -> Result<()> {
    let output = Command::new("ip")
        .arg(family)
        .args(arguments)
        .output()
        .context("execute iproute2")?;
    if !output.status.success() {
        let message = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        bail!("iproute2 exited with {}: {message}", output.status)
    }
    Ok(())
}

fn run_ip_delete(family: &str, arguments: &[String]) -> Result<()> {
    let output = Command::new("ip")
        .arg(family)
        .args(arguments)
        .output()
        .context("execute iproute2 cleanup")?;
    if output.status.success() {
        return Ok(());
    }
    let message = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    // Routes attached to a TUN interface are removed by the kernel when the
    // final device handle closes. During process-wide cancellation Tokio may
    // close that handle before this guard is polled for cleanup.
    if message.contains("Cannot find device")
        || message.contains("No such process")
        || message.contains("No such file or directory")
        || message.contains("FIB table does not exist")
    {
        return Ok(());
    }
    bail!("iproute2 cleanup exited with {}: {message}", output.status)
}

fn build_actions(config: &TunConfig) -> Result<Vec<IpAction>> {
    let mut actions = Vec::new();
    let has_v4 = config
        .addresses
        .iter()
        .any(|address| address.addr().is_ipv4());
    let has_v6 = config
        .addresses
        .iter()
        .any(|address| address.addr().is_ipv6());
    if has_v4 {
        build_family_actions(config, false, &mut actions)?;
    }
    if has_v6 {
        build_family_actions(config, true, &mut actions)?;
    }
    if config.strict_route {
        if !has_v4 {
            actions.push(IpAction::rule(
                "-4",
                config.rule_index,
                vec!["unreachable".into()],
            ));
        }
        if !has_v6 {
            actions.push(IpAction::rule(
                "-6",
                config.rule_index,
                vec!["unreachable".into()],
            ));
        }
    }
    Ok(actions)
}

fn build_family_actions(config: &TunConfig, ipv6: bool, actions: &mut Vec<IpAction>) -> Result<()> {
    let family = if ipv6 { "-6" } else { "-4" };
    let table = config.table_index;
    let mut routes = config
        .route_addresses
        .iter()
        .copied()
        .filter(|prefix| prefix.addr().is_ipv6() == ipv6)
        .collect::<Vec<_>>();
    if routes.is_empty() && !config.route_include_active {
        routes.push(if ipv6 {
            "::/0".parse().unwrap()
        } else {
            "0.0.0.0/0".parse().unwrap()
        });
    }
    for route in routes {
        actions.push(IpAction::route(
            family,
            route,
            &config.interface_name,
            table,
        ));
    }

    if config.auto_redirect {
        actions.push(IpAction::rule(
            family,
            config.rule_index,
            vec![
                "fwmark".into(),
                format!("0x{:x}", config.redirect_output_mark),
                "goto".into(),
                (config.rule_index + 2).to_string(),
            ],
        ));
        actions.push(IpAction::rule(
            family,
            config.rule_index + 1,
            vec![
                "fwmark".into(),
                format!("0x{:x}", config.redirect_input_mark),
                "lookup".into(),
                table.to_string(),
            ],
        ));
        actions.push(IpAction::rule(
            family,
            config.rule_index + 2,
            vec!["nop".into()],
        ));
        return Ok(());
    }

    let mut priority = config.rule_index;
    for prefix in config
        .route_exclude_addresses
        .iter()
        .filter(|prefix| prefix.addr().is_ipv6() == ipv6)
    {
        actions.push(IpAction::rule(
            family,
            priority,
            vec![
                "to".into(),
                prefix.to_string(),
                "lookup".into(),
                "main".into(),
            ],
        ));
        priority = next_priority(priority)?;
    }
    for uid in &config.exclude_uids {
        actions.push(IpAction::rule(
            family,
            priority,
            vec![
                "uidrange".into(),
                format!("{uid}-{uid}"),
                "lookup".into(),
                "main".into(),
            ],
        ));
        priority = next_priority(priority)?;
    }
    for (start, end) in &config.exclude_uid_ranges {
        actions.push(IpAction::rule(
            family,
            priority,
            vec![
                "uidrange".into(),
                format!("{start}-{end}"),
                "lookup".into(),
                "main".into(),
            ],
        ));
        priority = next_priority(priority)?;
    }
    for interface in &config.exclude_interfaces {
        actions.push(IpAction::rule(
            family,
            priority,
            vec![
                "iif".into(),
                interface.clone(),
                "lookup".into(),
                "main".into(),
            ],
        ));
        priority = next_priority(priority)?;
    }

    actions.push(IpAction::rule(
        family,
        priority,
        vec![
            "lookup".into(),
            "main".into(),
            "suppress_prefixlength".into(),
            "0".into(),
        ],
    ));
    priority = next_priority(priority)?;

    if config.include_uids.is_empty() && config.include_uid_ranges.is_empty() {
        for address in config
            .addresses
            .iter()
            .filter(|address| address.addr().is_ipv6() == ipv6)
        {
            actions.push(IpAction::rule(
                family,
                priority,
                vec![
                    "iif".into(),
                    "lo".into(),
                    "from".into(),
                    address.trunc().to_string(),
                    "lookup".into(),
                    table.to_string(),
                ],
            ));
            priority = next_priority(priority)?;
        }
        let unspecified = if ipv6 { "::/128" } else { "0.0.0.0/32" };
        actions.push(IpAction::rule(
            family,
            priority,
            vec![
                "iif".into(),
                "lo".into(),
                "from".into(),
                unspecified.into(),
                "lookup".into(),
                table.to_string(),
            ],
        ));
        priority = next_priority(priority)?;
    } else {
        for uid in &config.include_uids {
            actions.push(IpAction::rule(
                family,
                priority,
                vec![
                    "uidrange".into(),
                    format!("{uid}-{uid}"),
                    "lookup".into(),
                    table.to_string(),
                ],
            ));
            priority = next_priority(priority)?;
        }
        for (start, end) in &config.include_uid_ranges {
            actions.push(IpAction::rule(
                family,
                priority,
                vec![
                    "uidrange".into(),
                    format!("{start}-{end}"),
                    "lookup".into(),
                    table.to_string(),
                ],
            ));
            priority = next_priority(priority)?;
        }
    }

    if config.include_interfaces.is_empty() {
        actions.push(IpAction::rule(
            family,
            priority,
            vec![
                "not".into(),
                "iif".into(),
                "lo".into(),
                "lookup".into(),
                table.to_string(),
            ],
        ));
    } else {
        for interface in &config.include_interfaces {
            actions.push(IpAction::rule(
                family,
                priority,
                vec![
                    "iif".into(),
                    interface.clone(),
                    "lookup".into(),
                    table.to_string(),
                ],
            ));
            priority = next_priority(priority)?;
        }
    }
    Ok(())
}

fn next_priority(priority: u32) -> Result<u32> {
    priority
        .checked_add(1)
        .filter(|value| *value < 32766)
        .context("TUN policy rule priority overflow")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> TunConfig {
        TunConfig {
            interface_name: "xhttp0".into(),
            mtu: 1500,
            addresses: vec!["172.19.0.1/30".parse().unwrap()],
            stack: "smoltcp".into(),
            auto_route: true,
            auto_redirect: false,
            strict_route: false,
            route_addresses: Vec::new(),
            route_exclude_addresses: Vec::new(),
            route_include_active: false,
            route_exclude_active: false,
            include_interfaces: Vec::new(),
            exclude_interfaces: Vec::new(),
            include_uids: Vec::new(),
            exclude_uids: Vec::new(),
            include_uid_ranges: Vec::new(),
            exclude_uid_ranges: Vec::new(),
            table_index: 2022,
            rule_index: 9000,
            redirect_input_mark: 0x2023,
            redirect_output_mark: 0x2024,
            include_macs: Vec::new(),
            exclude_macs: Vec::new(),
            bypass_addresses: Vec::new(),
            udp_timeout: std::time::Duration::from_secs(300),
            udp_mapping: crate::tun::UdpNatBehavior::EndpointIndependent,
            udp_filtering: crate::tun::UdpNatBehavior::EndpointIndependent,
            udp_nat_max: 16_384,
        }
    }

    #[test]
    fn default_plan_uses_dedicated_table_and_reversible_rules() {
        let actions = build_actions(&config()).unwrap();
        assert!(actions.iter().any(|action| {
            action.add
                == [
                    "route",
                    "add",
                    "0.0.0.0/0",
                    "dev",
                    "xhttp0",
                    "table",
                    "2022",
                ]
        }));
        assert!(actions.iter().any(|action| {
            action
                .add
                .iter()
                .any(|value| value == "suppress_prefixlength")
        }));
        assert!(actions.iter().all(|action| {
            action.add[0] == action.delete[0]
                && action.add[2..] == action.delete[2..]
                && action.add[1] == "add"
                && action.delete[1] == "del"
        }));
    }

    #[test]
    fn selectors_and_strict_family_generate_specific_rules() {
        let mut value = config();
        value.strict_route = true;
        value.route_addresses = vec!["1.1.1.0/24".parse().unwrap()];
        value.route_exclude_addresses = vec!["1.1.1.1/32".parse().unwrap()];
        value.include_uids = vec![1000];
        value.include_interfaces = vec!["eth0".into()];
        let actions = build_actions(&value).unwrap();
        let rendered = actions
            .iter()
            .map(|action| format!("{} {}", action.family, action.add.join(" ")))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(rendered.contains("route add 1.1.1.0/24"));
        assert!(rendered.contains("to 1.1.1.1/32 lookup main"));
        assert!(rendered.contains("uidrange 1000-1000 lookup 2022"));
        assert!(rendered.contains("iif eth0 lookup 2022"));
        assert!(rendered.contains("-6 rule add priority 9000 unreachable"));
    }

    #[test]
    fn auto_redirect_plan_routes_only_input_mark_and_skips_output_mark() {
        let mut value = config();
        value.auto_redirect = true;
        let actions = build_actions(&value).unwrap();
        let rendered = actions
            .iter()
            .map(|action| format!("{} {}", action.family, action.add.join(" ")))
            .collect::<Vec<_>>()
            .join("\n");

        assert!(rendered.contains("priority 9000 fwmark 0x2024 goto 9002"));
        assert!(rendered.contains("priority 9001 fwmark 0x2023 lookup 2022"));
        assert!(rendered.contains("priority 9002 nop"));
        assert!(!rendered.contains("suppress_prefixlength"));
    }

    #[test]
    fn family_specific_include_does_not_capture_the_other_family() {
        let mut value = config();
        value
            .addresses
            .push("fdfe:dcba:9876::1/126".parse().unwrap());
        value.route_include_active = true;
        value.route_addresses = vec!["192.0.2.0/24".parse().unwrap()];
        let actions = build_actions(&value).unwrap();
        assert!(actions.iter().any(|action| {
            action.family == "-4" && action.add.iter().any(|value| value == "192.0.2.0/24")
        }));
        assert!(!actions.iter().any(|action| {
            action.family == "-6" && action.add.iter().any(|value| value == "::/0")
        }));
    }
}

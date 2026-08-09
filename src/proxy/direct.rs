use crate::{
    dns::DnsResolver,
    routing::RouteOptions,
    vless,
};
use anyhow::{Context, Result, bail};
use futures_util::{StreamExt, stream::FuturesUnordered};
use std::net::{IpAddr, SocketAddr};
use tokio::net::{TcpStream, UdpSocket};

use super::parse_duration;

pub(super) async fn connect_direct(
    destination: &vless::Destination,
    resolver: Option<&DnsResolver>,
    options: &RouteOptions,
) -> Result<TcpStream> {
    let timeout_duration = options
        .connect_timeout
        .as_deref()
        .map(|value| parse_duration(Some(value)))
        .unwrap_or(std::time::Duration::from_secs(10));
    let mut addresses = match destination {
        vless::Destination::Ip(ip, port) => vec![SocketAddr::new(*ip, *port)],
        vless::Destination::Domain(host, p) => {
            if let Some(r) = resolver {
                r.lookup(host)
                    .await?
                    .into_iter()
                    .map(|address| SocketAddr::new(address, *p))
                    .collect()
            } else {
                tokio::net::lookup_host((host.as_str(), *p))
                    .await?
                    .collect()
            }
        }
    };
    order_addresses(
        &mut addresses,
        options
            .domain_strategy
            .as_deref()
            .or(options.network_strategy.as_deref()),
    );
    if addresses.is_empty() {
        bail!("direct connection strategy selected no addresses")
    }
    let fallback_delay = options
        .fallback_delay
        .as_deref()
        .map(|value| parse_duration(Some(value)))
        .unwrap_or_else(|| std::time::Duration::from_millis(300));
    let mut pending = FuturesUnordered::new();
    let mut addresses = addresses.into_iter();
    if let Some(address) = addresses.next() {
        pending.push(connect_direct_address(address, timeout_duration, options));
    }
    let mut next_address = addresses.next();
    let mut last_error = None;
    loop {
        if next_address.is_none() {
            match pending.next().await {
                Some(Ok(stream)) => return Ok(stream),
                Some(Err(error)) => {
                    last_error = Some(error);
                    continue;
                }
                None => break,
            }
        }
        tokio::select! {
            result = pending.next() => match result {
                Some(Ok(stream)) => return Ok(stream),
                Some(Err(error)) => {
                    last_error = Some(error);
                    if pending.is_empty()
                        && let Some(address) = next_address.take()
                    {
                        pending.push(connect_direct_address(address, timeout_duration, options));
                        next_address = addresses.next();
                    }
                }
                None => unreachable!("at least one direct connection attempt is pending"),
            },
            () = tokio::time::sleep(fallback_delay) => {
                if let Some(address) = next_address.take() {
                    pending.push(connect_direct_address(address, timeout_duration, options));
                    next_address = addresses.next();
                }
            }
        }
    }
    Err(last_error
        .unwrap_or_else(|| anyhow::anyhow!("all direct connection attempts failed"))
        .context("all direct connection attempts failed"))
}
async fn connect_direct_address(
    address: SocketAddr,
    timeout_duration: std::time::Duration,
    options: &RouteOptions,
) -> Result<TcpStream> {
    let socket = if address.is_ipv4() {
        tokio::net::TcpSocket::new_v4()?
    } else {
        tokio::net::TcpSocket::new_v6()?
    };
    socket.set_reuseaddr(options.reuse_addr)?;
    if let Some(bind) = if address.is_ipv4() {
        options.inet4_bind_address.as_deref()
    } else {
        options.inet6_bind_address.as_deref()
    } {
        socket.bind(SocketAddr::new(bind.parse()?, 0))?;
    }
    set_linux_socket_options(&socket, options)?;
    tokio::time::timeout(timeout_duration, socket.connect(address))
        .await
        .with_context(|| format!("connect to {address} timed out"))?
        .with_context(|| format!("connect to {address}"))
}
fn order_addresses(addresses: &mut Vec<SocketAddr>, strategy: Option<&str>) {
    match strategy.unwrap_or("") {
        "ipv4_only" => addresses.retain(SocketAddr::is_ipv4),
        "ipv6_only" => addresses.retain(SocketAddr::is_ipv6),
        "prefer_ipv4" => addresses.sort_by_key(|address| !address.is_ipv4()),
        "prefer_ipv6" => addresses.sort_by_key(SocketAddr::is_ipv4),
        _ => {}
    }
}
pub(super) fn direct_udp_socket(target: SocketAddr, options: &RouteOptions) -> Result<UdpSocket> {
    let configured = if target.is_ipv4() {
        options.inet4_bind_address.as_deref()
    } else {
        options.inet6_bind_address.as_deref()
    };
    let bind_ip = configured
        .map(str::parse)
        .transpose()
        .context("invalid UDP bind address")?
        .unwrap_or(if target.is_ipv4() {
            IpAddr::from([0, 0, 0, 0])
        } else {
            IpAddr::from([0u16; 8])
        });
    if bind_ip.is_ipv4() != target.is_ipv4() {
        bail!("UDP bind address family does not match destination")
    }
    let socket = std::net::UdpSocket::bind(SocketAddr::new(bind_ip, 0))?;
    socket.set_nonblocking(true)?;
    set_linux_udp_socket_options(&socket, options)?;
    UdpSocket::from_std(socket).context("create asynchronous UDP socket")
}
#[cfg(target_os = "linux")]
fn set_linux_udp_socket_options(
    socket: &std::net::UdpSocket,
    options: &RouteOptions,
) -> Result<()> {
    use std::{ffi::CString, os::fd::AsRawFd};
    let descriptor = socket.as_raw_fd();
    let set = |level, name, value: &libc::c_int, operation: &str| -> Result<()> {
        let result = unsafe {
            libc::setsockopt(
                descriptor,
                level,
                name,
                (value as *const libc::c_int).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if result != 0 {
            return Err(std::io::Error::last_os_error()).context(operation.to_owned());
        }
        Ok(())
    };
    if options.reuse_addr {
        set(
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            &1,
            "enable UDP address reuse",
        )?;
    }
    if let Some(interface) = &options.bind_interface {
        let interface = CString::new(interface.as_str()).context("invalid bind_interface")?;
        let result = unsafe {
            libc::setsockopt(
                descriptor,
                libc::SOL_SOCKET,
                libc::SO_BINDTODEVICE,
                interface.as_ptr().cast(),
                interface.as_bytes_with_nul().len() as libc::socklen_t,
            )
        };
        if result != 0 {
            return Err(std::io::Error::last_os_error()).context("bind UDP socket to interface");
        }
    }
    if let Some(mark) = options.routing_mark {
        let mark = mark as libc::c_int;
        set(
            libc::SOL_SOCKET,
            libc::SO_MARK,
            &mark,
            "set UDP socket mark",
        )?;
    }
    if let Some(fragment) = options.udp_fragment {
        let discovery = if fragment {
            libc::IP_PMTUDISC_WANT
        } else {
            libc::IP_PMTUDISC_DO
        };
        set(
            libc::IPPROTO_IP,
            libc::IP_MTU_DISCOVER,
            &discovery,
            "configure UDP fragmentation",
        )?;
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn set_linux_udp_socket_options(
    _socket: &std::net::UdpSocket,
    options: &RouteOptions,
) -> Result<()> {
    if options.bind_interface.is_some()
        || options.routing_mark.is_some()
        || options.udp_fragment.is_some()
    {
        bail!("Linux UDP socket options are unavailable on this platform")
    }
    Ok(())
}
#[cfg(target_os = "linux")]
fn set_linux_socket_options(socket: &tokio::net::TcpSocket, options: &RouteOptions) -> Result<()> {
    use std::{ffi::CString, os::fd::AsRawFd};
    let descriptor = socket.as_raw_fd();
    if let Some(interface) = &options.bind_interface {
        let interface = CString::new(interface.as_str()).context("invalid bind_interface")?;
        let result = unsafe {
            libc::setsockopt(
                descriptor,
                libc::SOL_SOCKET,
                libc::SO_BINDTODEVICE,
                interface.as_ptr().cast(),
                interface.as_bytes_with_nul().len() as libc::socklen_t,
            )
        };
        if result != 0 {
            return Err(std::io::Error::last_os_error()).context("bind socket to interface");
        }
    }
    if let Some(mark) = options.routing_mark {
        let result = unsafe {
            libc::setsockopt(
                descriptor,
                libc::SOL_SOCKET,
                libc::SO_MARK,
                (&mark as *const u32).cast(),
                std::mem::size_of::<u32>() as libc::socklen_t,
            )
        };
        if result != 0 {
            return Err(std::io::Error::last_os_error()).context("set socket routing mark");
        }
    }
    if options.tcp_fast_open {
        let enabled: libc::c_int = 1;
        let result = unsafe {
            libc::setsockopt(
                descriptor,
                libc::IPPROTO_TCP,
                libc::TCP_FASTOPEN_CONNECT,
                (&enabled as *const libc::c_int).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if result != 0 {
            return Err(std::io::Error::last_os_error()).context("enable TCP Fast Open");
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn set_linux_socket_options(_socket: &tokio::net::TcpSocket, options: &RouteOptions) -> Result<()> {
    if options.bind_interface.is_some() || options.routing_mark.is_some() || options.tcp_fast_open {
        bail!("Linux direct socket options are unavailable on this platform")
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(ip: &str, port: u16) -> SocketAddr {
        if ip.contains(':') {
            format!("[{ip}]:{port}").parse().unwrap()
        } else {
            format!("{ip}:{port}").parse().unwrap()
        }
    }

    #[test]
    fn order_addresses_filters_and_sorts_by_strategy() {
        let v4a = addr("192.0.2.1", 80);
        let v4b = addr("192.0.2.2", 80);
        let v6a = addr("2001:db8::1", 80);
        let v6b = addr("2001:db8::2", 80);

        let mut addresses = vec![v4a, v6a, v4b, v6b];
        order_addresses(&mut addresses, Some("ipv4_only"));
        assert_eq!(addresses, vec![v4a, v4b]);

        let mut addresses = vec![v4a, v6a];
        order_addresses(&mut addresses, Some("ipv6_only"));
        assert_eq!(addresses, vec![v6a]);

        let mut addresses = vec![v6a, v4a];
        order_addresses(&mut addresses, Some("prefer_ipv4"));
        assert_eq!(addresses, vec![v4a, v6a]);

        let mut addresses = vec![v4a, v6a];
        order_addresses(&mut addresses, Some("prefer_ipv6"));
        assert_eq!(addresses, vec![v6a, v4a]);

        // Unknown and empty strategies keep the order.
        let mut addresses = vec![v6a, v4a, v6b];
        order_addresses(&mut addresses, Some("garbage"));
        assert_eq!(addresses, vec![v6a, v4a, v6b]);
        let mut addresses = vec![v6a, v4a];
        order_addresses(&mut addresses, None);
        assert_eq!(addresses, vec![v6a, v4a]);
    }

    #[test]
    fn order_addresses_empty_input_is_safe() {
        let mut addresses: Vec<SocketAddr> = Vec::new();
        order_addresses(&mut addresses, Some("ipv4_only"));
        order_addresses(&mut addresses, Some("prefer_ipv6"));
        assert!(addresses.is_empty());
    }
}

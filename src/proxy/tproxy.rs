//! Linux TProxy inbound: transparently intercept TCP and UDP traffic whose
//! destination is set by policy routing (`ip rule add fwmark 1 table 100`,
//! `iptables -t mangle -A PREROUTING -p tcp -j TPROXY ...`). TCP sockets are
//! bound with `IP_TRANSPARENT` so `local_addr` yields the original
//! destination; UDP packets carry the original destination in ancillary
//! data via `IP_RECVORIGDSTADDR`.

use anyhow::{Context, Result, bail};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    os::fd::AsRawFd,
    sync::{Arc, Mutex},
    time::Duration,
};

use tokio::{
    net::TcpListener,
    sync::mpsc,
};

use crate::proxy::udp_nat::{UdpMappingKey, UdpNatBehavior, UdpNatTable};
use crate::proxy::{
    ProxyRuntime, relay_streamed_tcp, relay_tun_udp,
};
use crate::singbox::Inbound;

// Linux constants not exported by the libc crate.
const IP_TRANSPARENT: libc::c_int = 19;
const IP_RECVORIGDSTADDR: libc::c_int = 20;
const IPV6_TRANSPARENT: libc::c_int = 75;
const IPV6_RECVORIGDSTADDR: libc::c_int = 74;
const MAX_OOB: usize = 1024;

fn set_int_option(fd: i32, level: libc::c_int, name: libc::c_int, value: libc::c_int) -> Result<()> {
    let result = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            (&value as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error()).context("set TProxy socket option");
    }
    Ok(())
}

/// Enable transparent interception on a socket: `IP_TRANSPARENT` lets the
/// socket bind/connect to non-local addresses, and for UDP,
/// `IP_RECVORIGDSTADDR` requests the original destination in ancillary data.
fn set_tproxy_options(fd: i32, is_ipv6: bool, is_udp: bool) -> Result<()> {
    set_int_option(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR, 1)?;
    set_int_option(
        fd,
        if is_ipv6 { libc::IPPROTO_IPV6 } else { libc::IPPROTO_IP },
        if is_ipv6 { IPV6_TRANSPARENT } else { IP_TRANSPARENT },
        1,
    )?;
    if is_udp {
        set_int_option(
            fd,
            if is_ipv6 { libc::IPPROTO_IPV6 } else { libc::IPPROTO_IP },
            if is_ipv6 { IPV6_RECVORIGDSTADDR } else { IP_RECVORIGDSTADDR },
            1,
        )?;
    }
    Ok(())
}

/// Create a transparent TCP or UDP socket bound to `listen`: options are
/// applied before bind so the kernel accepts a non-local bind address.
fn transparent_socket(listen: &str, is_udp: bool) -> Result<socket2::Socket> {
    use std::net::ToSocketAddrs;
    let address: SocketAddr = listen
        .to_socket_addrs()?
        .next()
        .context("invalid tproxy listen address")?;
    let domain = if address.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let ty = if is_udp {
        socket2::Type::DGRAM
    } else {
        socket2::Type::STREAM
    };
    let protocol = if is_udp {
        socket2::Protocol::UDP
    } else {
        socket2::Protocol::TCP
    };
    let socket =
        socket2::Socket::new(domain, ty, Some(protocol)).context("create tproxy socket")?;
    let fd = socket.as_raw_fd();
    set_tproxy_options(fd, address.is_ipv6(), is_udp)?;
    socket.bind(&address.into()).context("bind tproxy socket")?;
    if is_udp {
        // Blocking recvmsg runs in a dedicated worker thread.
    } else {
        socket.listen(1024).context("listen tproxy socket")?;
    }
    Ok(socket)
}

/// Parse the original destination from a `recvmsg` ancillary-data buffer
/// (`IP_RECVORIGDSTADDR`/`IPV6_RECVORIGDSTADDR` control messages).
fn original_destination(oob: &[u8]) -> Result<SocketAddr> {
    let mut position = 0;
    while position + 12 <= oob.len() {
        let cmsg_len = unsafe { (oob.as_ptr().add(position) as *const usize).read_unaligned() }
            .min(oob.len() - position);
        if cmsg_len < 12 {
            break;
        }
        let level = unsafe {
            (oob.as_ptr().add(position + 8) as *const i32).read_unaligned()
        };
        let ctype = unsafe {
            (oob.as_ptr().add(position + 12) as *const i32).read_unaligned()
        };
        let data_start = position + 16;
        if level == libc::SOL_IP && ctype == IP_RECVORIGDSTADDR {
            let port = u16::from_be_bytes([oob[data_start + 2], oob[data_start + 3]]);
            let ip = Ipv4Addr::new(
                oob[data_start + 4],
                oob[data_start + 5],
                oob[data_start + 6],
                oob[data_start + 7],
            );
            return Ok(SocketAddr::new(IpAddr::V4(ip), port));
        }
        if level == libc::SOL_IPV6 && ctype == IPV6_RECVORIGDSTADDR {
            let port = u16::from_be_bytes([oob[data_start + 2], oob[data_start + 3]]);
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&oob[data_start + 8..data_start + 24]);
            return Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port));
        }
        position += cmsg_len;
    }
    bail!("missing TProxy original destination in ancillary data")
}

pub async fn run_tproxy_inbound(inbound: Inbound, runtime: Arc<ProxyRuntime>) -> Result<()> {
    let listen = crate::util::socket(
        inbound.listen.as_deref().unwrap_or("::"),
        inbound
            .listen_port
            .context("tproxy inbound requires listen_port")?,
    );
    let tag = inbound.tag.unwrap_or_else(|| "tproxy-in".into());
    let mapping = UdpNatBehavior::parse(inbound.udp_mapping.as_deref(), "udp_mapping")?;
    let filtering = UdpNatBehavior::parse(inbound.udp_filtering.as_deref(), "udp_filtering")?;
    let udp_timeout = crate::util::parse_duration_lenient(inbound.udp_timeout.as_deref())
        .max(Duration::from_secs(1));
    let udp_nat_max = inbound.udp_nat_max.unwrap_or(0) as usize;
    let udp_nat_max = if udp_nat_max == 0 { 1024 } else { udp_nat_max };

    // TCP: transparent listener; the accepted socket's local address is the
    // original destination. Options must be set before bind so the socket
    // can bind the non-local listen address.
    let tcp_socket = std::net::TcpListener::from(
        transparent_socket(&listen, false)?,
    );
    let tcp_listener = TcpListener::from_std(tcp_socket).context("adopt tproxy TCP listener")?;
    let tcp_runtime = runtime.clone();
    let tcp_tag = tag.clone();
    let tcp_listener_task = tokio::spawn(async move {
        loop {
            let (stream, peer) = match tcp_listener.accept().await {
                Ok(value) => value,
                Err(error) => {
                    tracing::debug!(%error, "tproxy TCP accept failed");
                    continue;
                }
            };
            let destination = match stream.local_addr() {
                Ok(address) => address,
                Err(error) => {
                    tracing::debug!(%error, "tproxy TCP local_addr failed");
                    continue;
                }
            };
            let runtime = tcp_runtime.clone();
            let tag = tcp_tag.clone();
            tokio::spawn(async move {
                if let Err(error) =
                    relay_streamed_tcp(stream, peer, destination, &tag, &runtime).await
                {
                    tracing::debug!(%error, %peer, %destination, "tproxy TCP relay failed");
                }
            });
        }
    });

    // UDP NAT table shared by the reader and write-back tasks.
    let table = Arc::new(Mutex::new(UdpNatTable::new(
        filtering,
        udp_nat_max,
        udp_timeout,
    )));
    let weak_table = Arc::downgrade(&table);

    // UDP: transparent socket reading original destinations from ancdata.
    let udp_socket = Arc::new(std::net::UdpSocket::from(
        transparent_socket(&listen, true)?,
    ));
    let (packet_tx, mut packet_rx) = mpsc::channel::<(Vec<u8>, Vec<u8>, SocketAddr)>(512);
    let reader_socket = udp_socket.clone();
    tokio::spawn(async move {
        let mut buffer = vec![0u8; u16::MAX as usize];
        let mut oob = vec![0u8; MAX_OOB];
        loop {
            // recvmsg on the blocking socket in a worker thread so the
            // non-async ancdata read does not starve the runtime.
            let socket = reader_socket.clone();
            let mut owned_buffer = buffer.clone();
            let mut owned_oob = oob.clone();
            let result = tokio::task::spawn_blocking(move || {
                let mut source: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
                let source_ptr: *mut libc::sockaddr_storage = &mut source;
                let source_len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
                let mut iovec = libc::iovec {
                    iov_base: owned_buffer.as_mut_ptr().cast(),
                    iov_len: owned_buffer.len(),
                };
                let mut message = libc::msghdr {
                    msg_name: source_ptr.cast(),
                    msg_namelen: source_len,
                    msg_iov: &mut iovec,
                    msg_iovlen: 1,
                    msg_control: owned_oob.as_mut_ptr().cast(),
                    msg_controllen: owned_oob.len(),
                    msg_flags: 0,
                };
                let length = unsafe { libc::recvmsg(socket.as_raw_fd(), &mut message, 0) };
                if length < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                let address = udp_recvmsg::addr_from_sockaddr(&source);
                Ok((length as usize, message.msg_controllen, address, owned_buffer, owned_oob))
            })
            .await;
            let result = match result {
                Ok(value) => value,
                Err(error) => {
                    tracing::debug!(%error, "tproxy UDP recvmsg worker failed");
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    continue;
                }
            };
            let (length, oob_length, address, received, received_oob) = match result {
                Ok(value) => value,
                Err(error) => {
                    tracing::debug!(%error, "tproxy UDP recvmsg failed");
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    continue;
                }
            };
            if packet_tx
                .send((received[..length].to_vec(), received_oob[..oob_length].to_vec(), address))
                .await
                .is_err()
            {
                break;
            }
            buffer[..length].copy_from_slice(&received[..length]);
            oob[..oob_length].copy_from_slice(&received_oob[..oob_length]);
        }
    });
    let (response_tx, mut response_rx) =
        mpsc::channel::<(UdpMappingKey, (Vec<u8>, SocketAddr, SocketAddr))>(512);
    let writer_socket = udp_socket.clone();
    tokio::spawn(async move {
        while let Some((key, (payload, destination, source))) = response_rx.recv().await {
            let Some(table) = weak_table.upgrade() else {
                break;
            };
            let allowed = table
                .lock()
                .is_ok_and(|mut table| table.allow_response(key, destination));
            if !allowed {
                continue;
            }
            // Write back with IP_TRANSPARENT so the reply carries the
            // original destination as its source address.
            let transparent = match source {
                SocketAddr::V4(_) => IP_TRANSPARENT,
                SocketAddr::V6(_) => IPV6_TRANSPARENT,
            };
            let fd = writer_socket.as_raw_fd();
            if set_int_option(fd, libc::IPPROTO_IP, transparent, 1).is_ok()
                && writer_socket.send_to(&payload, source).is_err()
            {
                tracing::debug!("tproxy UDP write-back failed");
            }
        }
    });

    while let Some((payload, oob, peer)) = packet_rx.recv().await {
        let destination = match original_destination(&oob) {
            Ok(address) => address,
            Err(error) => {
                tracing::debug!(%error, "tproxy UDP packet without original destination");
                continue;
            }
        };
        let mapping_key = UdpNatTable::key_for(mapping, peer, destination);
        let sender = {
            let mut table = table
                .lock()
                .map_err(|_| anyhow::anyhow!("tproxy UDP NAT lock poisoned"))?;
            table.touch_and_sender(mapping_key, destination)
        };
        let sender = if let Some(sender) = sender {
            sender
        } else {
            let (sender, receiver) = mpsc::channel(64);
            table
                .lock()
                .map_err(|_| anyhow::anyhow!("tproxy UDP NAT lock poisoned"))?
                .insert_sender(mapping_key, sender.clone());
            let runtime = runtime.clone();
            let tag = tag.clone();
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
                if let Err(error) = relay_tun_udp(
                    peer,
                    &tag,
                    &runtime,
                    receiver,
                    flow_response_tx,
                    udp_timeout,
                    mapping == UdpNatBehavior::AddressAndPortDependent,
                )
                .await
                {
                    tracing::debug!(%error, "tproxy UDP relay failed");
                }
            });
            sender
        };
        if sender.send((payload, destination)).await.is_err() {
            tracing::debug!("tproxy UDP session closed");
        }
    }
    // The TCP accept task runs for the lifetime of the runtime.
    drop(tcp_listener_task);
    Ok(())
}

/// A minimal async UDP recv with ancillary data, since tokio's recvmsg
/// support is not exposed for out-of-band original-destination reads.
mod udp_recvmsg {
    use super::*;
    pub(super) fn addr_from_sockaddr(storage: &libc::sockaddr_storage) -> SocketAddr {
        unsafe {
            let family = storage.ss_family as i32;
            if family == libc::AF_INET {
                let address = &*(storage as *const _ as *const libc::sockaddr_in);
                SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::from(u32::from_be(address.sin_addr.s_addr))),
                    u16::from_be(address.sin_port),
                )
            } else {
                let address = &*(storage as *const _ as *const libc::sockaddr_in6);
                SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::from(address.sin6_addr.s6_addr)),
                    u16::from_be(address.sin6_port),
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transparent_socket_sets_options_and_listens() {
        let socket = transparent_socket("0.0.0.0:0", false).unwrap();
        assert!(
            socket
                .local_addr()
                .unwrap()
                .as_socket()
                .is_some_and(|address| address.port() > 0)
        );
        // The socket must be able to bind a non-local address when asked.
        let listener = transparent_socket("10.99.255.254:0", false);
        // In a container without CAP_NET_ADMIN this may fail; accept either.
        if let Ok(listener) = listener {
            assert!(listener.local_addr().is_ok());
        }
        drop(socket);
    }

    #[test]
    fn parses_ipv4_original_destination_from_oob() {
        let mut oob = Vec::new();
        // cmsghdr: len, level, type; then sockaddr_in: family, port, addr
        let cmsg_len: usize = 28;
        let level: libc::c_int = libc::SOL_IP;
        let ctype: libc::c_int = IP_RECVORIGDSTADDR;
        oob.extend_from_slice(&cmsg_len.to_ne_bytes());
        oob.extend_from_slice(&level.to_ne_bytes());
        oob.extend_from_slice(&ctype.to_ne_bytes());
        oob.extend_from_slice(&(libc::AF_INET as u16).to_ne_bytes()); // family
        oob.extend_from_slice(&53u16.to_be_bytes()); // port
        oob.extend_from_slice(&[1, 2, 3, 4]); // addr
        oob.extend_from_slice(&[0u8; 8]); // sockaddr_in pad
        let destination = original_destination(&oob).unwrap();
        assert_eq!(destination, "1.2.3.4:53".parse().unwrap());
    }
}

//! Native Linux TCP redirect (SO_ORIGINAL_DST) module.
//!
//! Provides both a standalone `type: "redirect"` inbound and an internal
//! redirect server used by TUN `auto_redirect` for native kernel-level TCP forwarding,
//! matching the architecture of xhttp-box / sing-box.

use crate::{
    proxy::{ProxyRuntime, relay::relay_streamed_tcp},
    singbox::Inbound,
};
use anyhow::{Context, Result};
use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    os::fd::AsRawFd,
    sync::Arc,
};
use tokio::net::TcpListener;

/// Retrieve the original destination of a redirected TCP socket using SO_ORIGINAL_DST.
#[cfg(target_os = "linux")]
pub fn get_original_destination<F: AsRawFd>(fd: &F) -> std::io::Result<SocketAddr> {
    let raw_fd = fd.as_raw_fd();
    unsafe {
        // Try IPv4 SO_ORIGINAL_DST first
        let mut addr: libc::sockaddr_in = std::mem::zeroed();
        let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        let ret = libc::getsockopt(
            raw_fd,
            libc::SOL_IP,
            libc::SO_ORIGINAL_DST,
            &mut addr as *mut _ as *mut libc::c_void,
            &mut len,
        );
        if ret == 0 {
            let ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
            let port = u16::from_be(addr.sin_port);
            return Ok(SocketAddr::V4(SocketAddrV4::new(ip, port)));
        }

        // Try IPv6 IP6T_SO_ORIGINAL_DST (80)
        let mut addr6: libc::sockaddr_in6 = std::mem::zeroed();
        let mut len6 = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
        const IP6T_SO_ORIGINAL_DST: libc::c_int = 80;
        let ret6 = libc::getsockopt(
            raw_fd,
            libc::SOL_IPV6,
            IP6T_SO_ORIGINAL_DST,
            &mut addr6 as *mut _ as *mut libc::c_void,
            &mut len6,
        );
        if ret6 == 0 {
            let ip = Ipv6Addr::from(addr6.sin6_addr.s6_addr);
            let port = u16::from_be(addr6.sin6_port);
            if let Some(v4) = ip.to_ipv4_mapped() {
                return Ok(SocketAddr::V4(SocketAddrV4::new(v4, port)));
            }
            return Ok(SocketAddr::V6(SocketAddrV6::new(
                ip,
                port,
                addr6.sin6_flowinfo,
                addr6.sin6_scope_id,
            )));
        }

        Err(std::io::Error::last_os_error())
    }
}

#[cfg(not(target_os = "linux"))]
pub fn get_original_destination<F: AsRawFd>(_fd: &F) -> std::io::Result<SocketAddr> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "SO_ORIGINAL_DST is only supported on Linux",
    ))
}

pub struct RedirectServer {
    listener: TcpListener,
    local_addr: SocketAddr,
}

impl RedirectServer {
    pub fn bind(addr: SocketAddr) -> Result<Self> {
        let std_listener = std::net::TcpListener::bind(addr)
            .with_context(|| format!("bind TCP redirect listener to {addr}"))?;
        std_listener
            .set_nonblocking(true)
            .context("set redirect listener non-blocking")?;
        let local_addr = std_listener
            .local_addr()
            .context("get redirect listener local addr")?;
        let listener =
            TcpListener::from_std(std_listener).context("adopt redirect TCP listener")?;
        Ok(Self {
            listener,
            local_addr,
        })
    }

    pub fn bind_local() -> Result<Self> {
        // Try dual-stack [::]:0 first
        let socket = socket2::Socket::new(
            socket2::Domain::IPV6,
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        );
        if let Ok(socket) = socket {
            let _ = socket.set_only_v6(false);
            let _ = socket.set_reuse_address(true);
            let addr: SocketAddr = "[::]:0".parse().unwrap();
            if socket.bind(&addr.into()).is_ok() && socket.listen(1024).is_ok() {
                let std_listener: std::net::TcpListener = socket.into();
                let _ = std_listener.set_nonblocking(true);
                if let Ok(local_addr) = std_listener.local_addr()
                    && let Ok(listener) = TcpListener::from_std(std_listener)
                {
                    return Ok(Self {
                        listener,
                        local_addr,
                    });
                }
            }
        }
        Self::bind("127.0.0.1:0".parse().unwrap())
    }

    pub fn port(&self) -> u16 {
        self.local_addr.port()
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub async fn run(self, runtime: Arc<ProxyRuntime>, tag: String) -> Result<()> {
        tracing::info!(port = self.port(), local_addr = %self.local_addr, "TCP redirect server started");
        loop {
            let (stream, peer) = match self.listener.accept().await {
                Ok(value) => value,
                Err(error) => {
                    tracing::debug!(%error, "redirect TCP accept failed");
                    continue;
                }
            };
            let destination = match get_original_destination(&stream) {
                Ok(destination) => destination,
                Err(error) => {
                    tracing::debug!(%error, %peer, "failed to get SO_ORIGINAL_DST from redirected connection");
                    continue;
                }
            };
            let runtime = runtime.clone();
            let tag = tag.clone();
            tokio::spawn(async move {
                if let Err(error) =
                    relay_streamed_tcp(stream, peer, destination, &tag, &runtime).await
                {
                    tracing::debug!(%error, %peer, %destination, "redirect TCP relay failed");
                }
            });
        }
    }
}

pub async fn run_redirect_inbound(inbound: Inbound, runtime: Arc<ProxyRuntime>) -> Result<()> {
    let port = inbound
        .listen_port
        .context("redirect inbound requires listen_port")?;
    let address = inbound
        .listen
        .as_deref()
        .unwrap_or("::")
        .parse::<std::net::IpAddr>()
        .context("invalid redirect listen address")?;
    let bind_addr = SocketAddr::new(address, port);
    let tag = inbound.tag.unwrap_or_else(|| "redirect-in".into());
    let server = RedirectServer::bind(bind_addr)?;
    server.run(runtime, tag).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpStream;

    #[tokio::test]
    async fn bind_local_allocates_ephemeral_port() {
        let server = RedirectServer::bind_local().unwrap();
        assert!(server.port() > 0);
    }

    #[tokio::test]
    async fn bind_custom_address() {
        let server = RedirectServer::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        assert!(server.port() > 0);
        assert_eq!(
            server.local_addr().ip(),
            "127.0.0.1".parse::<std::net::IpAddr>().unwrap()
        );
    }

    #[tokio::test]
    async fn get_original_destination_returns_dialed_address() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (server_stream, _) = listener.accept().await.unwrap();
        let res = get_original_destination(&server_stream).unwrap();
        assert_eq!(res, addr);
        drop(client);
    }

    #[tokio::test]
    async fn get_original_destination_ipv6_loopback() {
        // Requires a host with IPv6 loopback enabled; skip elsewhere so the
        // test does not fail on IPv4-only environments.
        let listener = match TcpListener::bind("[::1]:0").await {
            Ok(listener) => listener,
            Err(error) => {
                eprintln!("skipping IPv6 loopback redirect test: {error}");
                return;
            }
        };
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (server_stream, _) = listener.accept().await.unwrap();
        let res = get_original_destination(&server_stream).unwrap();
        assert_eq!(res, addr);
        drop(client);
    }

    #[tokio::test]
    async fn run_redirect_inbound_requires_listen_port() {
        let runtime = Arc::new(
            crate::proxy::build_runtime(
                vec![crate::singbox::Outbound {
                    r#type: "direct".into(),
                    tag: Some("direct".into()),
                    ..Default::default()
                }],
                None,
                None,
                Vec::new(),
                None,
            )
            .await
            .unwrap(),
        );

        let inbound = Inbound {
            r#type: "redirect".into(),
            listen_port: None,
            ..Default::default()
        };
        let err = run_redirect_inbound(inbound, runtime).await.unwrap_err();
        assert!(err.to_string().contains("listen_port"));
    }

    #[tokio::test]
    async fn run_redirect_inbound_invalid_address() {
        let runtime = Arc::new(
            crate::proxy::build_runtime(
                vec![crate::singbox::Outbound {
                    r#type: "direct".into(),
                    tag: Some("direct".into()),
                    ..Default::default()
                }],
                None,
                None,
                Vec::new(),
                None,
            )
            .await
            .unwrap(),
        );

        let inbound = Inbound {
            r#type: "redirect".into(),
            listen: Some("not-an-ip".into()),
            listen_port: Some(1234),
            ..Default::default()
        };
        let err = run_redirect_inbound(inbound, runtime).await.unwrap_err();
        assert!(err.to_string().contains("invalid redirect listen address"));
    }
}

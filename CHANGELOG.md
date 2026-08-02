# Changelog

All notable changes to xhttp-rs are documented in this file.

## [0.1.0] - 2026-08-02

First public preview release.

### Highlights

- XHTTP client and server support for `stream-one`, `stream-up`, and
  `packet-up` over HTTP/1.1, HTTP/2, HTTP/2 cleartext, and HTTP/3.
- VLESS TCP, UDP, and XUDP support, including interoperable sing-box and
  Xray-core client/server operation.
- AnyTLS v2 inbound and outbound support with session reuse, padding,
  UDP-over-TCP, and ECH.
- SOCKS5, HTTP, mixed, and Linux TUN inbounds with shared routing and DNS
  handling.
- Linux TUN router mode with automatic policy routing, nftables redirect,
  hot-reloaded route address sets, and bounded LRU UDP NAT mappings.
- DNS over UDP, TCP, TLS, and HTTPS with caching, routing, and DNS hijacking.
- Inline, local, and remote source JSON and binary SRS rule-set support.
- Docker image containing the Linux routing utilities required by TUN mode.

### Preview status

- This is an early preview. Configuration and command-line compatibility may
  change before a stable release.
- TUN inbound and automatic routing are supported on Linux only and require a
  TUN device plus `CAP_NET_ADMIN` or equivalent root privileges.
- Android-specific TUN filters, explicit network namespaces, loopback address
  remapping, and Tailscale integration are not included in this release.

[0.1.0]: https://github.com/flyzstu/xhttp-rs/releases/tag/v0.1.0

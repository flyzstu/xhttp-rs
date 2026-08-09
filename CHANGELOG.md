# Changelog

All notable changes to xhttp-rs are documented in this file.

## [0.1.1] - 2026-08-09

### Performance

- Collect Linux route metadata (process, user, network, interface, MAC,
  hostname) lazily: the SOCKS/HTTP inbound skips the per-connection `/proc`
  scan and subprocess probes entirely when no route rule references those
  fields, with short-TTL caching for interface and default-interface data.
- Reduce route-matching allocations: the destination domain is normalized
  once per evaluation, suffix checks use `strip_suffix`, and rule-set
  matching only clones the route context when source-IP CIDR matching needs
  it.
- Parse the URI query lazily in metadata extraction instead of building a
  full `HashMap` on every request.
- Make DNS cache keys cheap to clone by using `Arc<str>` and `Arc<[u8]>`
  for their fields.
- Cache the parsed request URL and static headers in the XHTTP client so
  packet-up uploads clone the base instead of reparsing on every packet.
- Reuse owned `Bytes` for Body-placed packets and stream download responses
  into `BytesMut`, avoiding per-chunk copies.
- Reuse a thread-local scratch buffer for padding Huffman length checks.
- Merge XMUX pool selection into a single pass instead of three table scans.
- Reduce TUN UDP NAT lock contention: one locked call per packet for touch
  and sender lookup, and defer idle reclamation until the table is at
  capacity.
- Cache XUDP session targets so domain destinations resolve once per
  session instead of per frame.
- Skip the global DNS cache expiry pass on every hit; only the requested
  entry is checked, deferring table-wide reclamation to insert.

### Architecture

- Split the 3.3k-line `proxy.rs` into `mod/relay/inbound/route/udp/direct`
  submodules and the 1.8k-line `dns.rs` into `mod/cache/transport/message`,
  and extract shared helpers into `src/util.rs`.
- Split `SingBoxConfig::validate_runtime` into per-inbound and per-outbound
  checks, cutting the validator's cognitive complexity from 200 to 19.
- Add 47 unit tests covering the split modules and optimized paths.

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

[0.1.1]: https://github.com/flyzstu/xhttp-rs/releases/tag/v0.1.1
[0.1.0]: https://github.com/flyzstu/xhttp-rs/releases/tag/v0.1.0

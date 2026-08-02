# xhttp-rs

Rust implementation of the XHTTP transport used by sing-box and Xray-core.
It provides a VLESS/XHTTP server, SOCKS, HTTP, mixed and Linux TUN local proxy
clients, plus AnyTLS v2 client and server operation, using sing-box style JSON
configuration.

## Build and run

```bash
cargo build --release
./target/release/xhttp check -c config.json
./target/release/xhttp run -c config.json
```

The repository's [interop server configuration](tests/interop-rust-server.json)
is accepted directly. A minimal client configuration looks like:

```json
{
  "inbounds": [{
    "type": "mixed",
    "tag": "mixed-in",
    "listen": "127.0.0.1",
    "listen_port": 1080
  }],
  "outbounds": [{
    "type": "vless",
    "tag": "proxy",
    "server": "example.com",
    "server_port": 443,
    "uuid": "00000000-0000-0000-0000-000000000000",
    "tls": {"enabled": true, "server_name": "example.com"},
    "transport": {
      "type": "xhttp",
      "host": "example.com",
      "path": "/xhttp",
      "mode": "packet-up"
    }
  }],
  "route": {"final": "proxy"}
}
```

## Configuration examples

- [DNS](examples/dns.json) demonstrates UDP, DNS over TLS, DNS over HTTPS,
  local system resolution, per-domain server selection, bounded caching and
  DNS hijacking.
- [Rule-sets](examples/ruleset.json) demonstrates inline and local source
  rule-sets. Its local source data is in
  [ruleset-source.json](examples/ruleset-source.json).
- [TUN](examples/tun.json) demonstrates the Linux Tokio/smoltcp TUN inbound.

Validate either example from the repository root:

```bash
cargo run -- check -c examples/dns.json
cargo run -- check -c examples/ruleset.json
```

Remote source JSON and binary SRS rule-sets use the same route structure:

```json
{
  "type": "remote",
  "tag": "remote-rules",
  "format": "binary",
  "url": "https://example.com/rules.srs",
  "update_interval": "24h"
}
```

## Implemented protocol surface

- XHTTP `stream-one`, `stream-up`, `packet-up`, including h1, h2/h2c,
  HTTP/3/QUIC and TLS.
- Path, query, header and cookie metadata placements.
- Body, header, cookie and auto upload data placements.
- Standard and obfuscated padding, including HPACK-aware `tokenish` padding.
- XHTTP XMUX HTTP-client pools with connection/concurrency, reuse, request,
  lifetime and TCP keepalive budgets.
- Custom upload methods and the compatible gRPC/SSE header switches.
- VLESS TCP, classic UDP and XUDP with UUID authentication and IPv4, IPv6,
  and domain targets. A VLESS connection can carry multiple isolated XUDP
  sessions. SOCKS5 UDP ASSOCIATE preserves datagram boundaries.
- Static client ECH configuration over HTTP/1.1, HTTP/2 and HTTP/3. Both
  sing-box `ECH CONFIGS` PEM and RFC-style `ECHCONFIG` PEM are accepted.
- DNS over UDP, TCP, TLS, HTTPS and local resolution with multiplexed UDP,
  pooled TCP/DoT, shared TLS state, singleflight request coalescing, bounded
  TTL/LRU caching (including raw DNS messages), and per-domain upstream
  selection.
- Linux client routing with logical rules and matchers for domains, CIDRs,
  ports, source/auth user, process, executable, UID, interface/address,
  Wi-Fi, MAC/hostname, network type, protocol/client sniffing and inbound tag.
- Route, route-options, direct/bypass, reject/reset/drop/reply, sniff, resolve
  and `hijack-dns` actions for TCP and UDP. Direct dialing supports Linux
  interface/mark/bind/reuse/TFO and UDP connection, fragmentation and timeout
  options; TLS packet/record fragmentation is supported for direct TCP.
- Inline/local/remote sing-box source JSON and binary SRS rule-sets with a
  64 MiB limit, disk cache, stale-cache fallback and periodic atomic refresh.
- Direct, block and VLESS/XHTTP outbounds.
- AnyTLS v2 inbound and outbound with TLS, padding negotiation, session reuse,
  SYNACK timeout recovery, UDP-over-TCP v2, static or DNS-discovered client
  ECH, and server ECH key support.
- SOCKS5, HTTP proxy and mixed TCP inbounds, including username/password
  authentication and `auth_user` routing.
- Linux TUN inbound using `tun-rs` and a Tokio-driven smoltcp userspace stack.
  Extracted TCP and UDP flows use the same direct, AnyTLS, VLESS/XHTTP, routing,
  sniffing and DNS-hijack dispatcher as local proxy inbounds; ICMP echo is
  answered by the stack.

### Linux TUN routing

The TUN runtime can install Linux policy routes automatically. It detects and
binds the physical default interface before creating TUN unless
`default_interface` or `auto_detect_interface` is explicitly configured,
preventing direct outbound traffic from looping into TUN. The example limits
automatic routing to Cloudflare's public resolver addresses:

```bash
sudo cargo run -- run -c examples/tun.json
```

`auto_route` uses a dedicated iproute2 table and priority window (compatible
defaults: table `2022`, rule priority `9000`). `route_address` and
`route_exclude_address` select captured prefixes; `include_interface`,
`exclude_interface`, UID/UID-range selectors and `strict_route` are supported.
Every installed route/rule is rolled back on normal shutdown, cancellation,
or a partially failed setup. Use custom table/rule indexes when another VPN
already occupies the defaults, as shown in the example.

`auto_redirect` adds an atomic nftables capture plane for locally generated and
forwarded IPv4/IPv6 TCP, UDP and ICMP traffic. It supports ingress interface,
source MAC, UID, route-prefix and proxy/DNS endpoint bypass filters, marks proxy
outbound sockets to prevent loops, enables forwarding while active, and adds
Docker `DOCKER-USER` compatibility rules when that chain exists. A deterministic
table name and process lock recover stale nftables/policy-route state on the
next start and preserve the forwarding sysctl values that preceded a hard kill.
Unlike sing-tun, this data plane sends all selected protocols directly to the
TUN table and therefore does not need a TCP REDIRECT listener or NFQUEUE reset
path.

The TUN address accepts a scalar or a list of IPv4/IPv6 prefixes. Supported
stack names are `mixed`, `gvisor` (compatibility aliases) and `smoltcp`; all
use the Rust smoltcp data plane. Linux source-MAC filters and individual/ranged
UID filters are supported with `auto_redirect`. Android package/user filters,
explicit network namespaces and loopback address remapping remain unsupported
and fail validation.

`route_address_set` and `route_exclude_address_set` extract destination CIDRs
from inline, local, remote source-JSON and binary SRS rule-sets. Updates replace
the nftables interval sets and dedicated iproute2 routes without restarting the
TUN device; a failed reload retains the last valid rules. Local sets with an
`update_interval` and remote sets use the shared router refresh snapshot.

The TUN UDP NAT supports endpoint-independent, address-dependent and
address-and-port-dependent mapping and filtering independently. Mappings expire
after `udp_timeout`; `udp_nat_max` applies LRU eviction and closes every relay
owned by the evicted mapping. When the limit is zero or omitted, Linux memory
determines a value between 4096 and 16384. Direct, VLESS XUDP and AnyTLS UoT
preserve variable destinations inside endpoint-independent mappings.

## Verification

```bash
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
tests/interop.sh
sudo tests/tun-router-linux.sh
```

The interoperability suite builds the included sing-box and Xray-core trees
and tests TCP and UDP in both client/server directions for every XHTTP mode. It also covers
non-default placements, tokenish padding, custom upload methods, inline TLS
certificates, XMUX concurrency, client ECH over H1/H2/H3, TLS failure cases,
and a TLS `server_name` distinct from the dial address.

Six cargo-fuzz targets cover VLESS destinations, XUDP frames, SOCKS5 UDP,
DNS messages, cookies and XHTTP metadata. A repeatable short TCP/UDP load
probe and its current baseline are documented in
[doc/performance.md](doc/performance.md).

Run the local DNS cache and transport benchmark with:

```bash
cargo bench --bench dns
```

## License

Licensed under the [MIT License](LICENSE).

## Current boundaries

Legacy GeoIP/Geosite databases, fake-IP DNS, `preferred_by` outbounds,
remote rule-set `download_detour`, `packetaddr`, XHTTP DNS-discovered/server ECH
and mux.cool are not enabled. TUN package filters, explicit network namespaces,
loopback remapping and sing-tun's optional NFQUEUE pre-match path are not enabled.
Linux has no sing-box-compatible
`network_is_constrained`, `tcp_multi_path` or TLS spoof facility; unsupported
runtime-relevant options fail validation instead of being silently ignored.
Set `XHTTP_CLASH_MODE=direct|global|rule` when using `clash_mode` rules.

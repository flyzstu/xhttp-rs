# xhttp-rs Implementation Plan

Last updated: 2026-08-02

## Project goal

`xhttp-rs` is a standalone Rust implementation of the sing-box/Xray XHTTP,
VLESS and AnyTLS paths. It accepts a useful subset of sing-box JSON configuration and
can run as both:

- a VLESS/XHTTP server; and
- an AnyTLS v2 server; and
- a local SOCKS5, HTTP, mixed, or Linux TUN proxy client with direct, block,
  and VLESS/XHTTP or AnyTLS outbounds.

The current goal is not to rewrite every sing-box protocol and platform
feature. Compatibility work should prioritize the XHTTP/VLESS data path,
the sing-box configuration fields needed by that path, and verified
interoperability with sing-box and Xray-core.

## Current status

The implementation is usable rather than a protocol skeleton. At the time of
this update:

- `cargo test --all-targets` passes 68 tests;
- `cargo clippy --all-targets -- -D warnings` passes; and
- `tests/interop.sh` passes sing-box and Xray-core TCP/UDP interoperability in
  both client/server directions for all three XHTTP modes.

The interoperability suite also covers AnyTLS v2 TCP/UDP in both directions
with sing-box, non-default metadata/data placements,
tokenish padding, a custom upload method, XMUX under concurrent logical
connections, inline TLS certificates, expected TLS trust/hostname/ALPN
failures, static client ECH over H1/H2/H3, a TLS `server_name` distinct from
the dial address, and HTTP/3.

The current external compatibility baseline is:

- sing-box `79eca64a383e32316b2fcbfd105d1741e3526220`; and
- Xray-core `50231eaff98ccc31b5cbd247a721c16e97fe5ec1`.

Run all three checks before marking a protocol-level change complete:

```bash
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
tests/interop.sh
```

## Implemented capabilities

### XHTTP transport

- `stream-one`
- `stream-up`
- `packet-up`
- `auto`, currently resolved deterministically to `packet-up`
- HTTP/1.1
- HTTP/2 and h2c
- HTTP/3 over QUIC
- TLS with native roots, custom CA input, inline server PEM, or PEM files
- static client ECH from inline PEM or a PEM file over H1/H2/H3
- separate dial address, HTTP Host, and TLS `server_name`
- fixed path/query validation
- bearer token authorization
- custom request headers
- custom uplink HTTP methods
- compatible gRPC and SSE header switches
- XMUX HTTP-client pools with maximum connection/concurrency, logical reuse,
  HTTP request, reusable lifetime, and TCP keepalive budgets

Metadata placements:

- session ID in path, query, header, or cookie
- sequence number in path, query, header, or cookie
- padding in query, header, cookie, or query-in-header

Upload payload placements:

- body
- header
- cookie
- auto

Padding:

- standard `repeat-x`
- obfuscated padding
- HPACK-aware `tokenish`

The server enforces packet size, buffered packet, session count, session ID
length, timeout, ordering, and duplicate/session isolation limits.

### VLESS

- UUID authentication
- multiple inbound users
- TCP command
- classic length-prefixed UDP command
- XUDP packet encoding
- IPv4, IPv6, and domain destinations
- client and server operation over every supported XHTTP mode
- multiple isolated XUDP sessions on one VLESS connection

The XUDP server bounds one VLESS connection to 256 concurrent XUDP sessions
and gives each session an independent UDP socket, destination state, queue,
idle timeout, and close lifecycle.

### Local proxy inbounds

- SOCKS5 TCP CONNECT
- SOCKS5 UDP ASSOCIATE
- HTTP proxy CONNECT
- HTTP proxy absolute-form request rewriting
- mixed SOCKS5/HTTP TCP detection

SOCKS5 UDP preserves datagram boundaries and can route through direct,
classic VLESS UDP, or XUDP paths.

### Linux TUN inbound

- native L3 device creation/configuration through `tun-rs`
- Tokio packet pumps between the device and the smoltcp userspace stack
- TCP, UDP and ICMP extraction/handling
- TCP/UDP dispatch through direct, AnyTLS and VLESS/XHTTP outbounds
- normal route actions, sniffing, route options and DNS hijacking
- IPv4 and IPv6 device addresses with explicit MTU and interface name
- Linux automatic policy routing in a dedicated table/priority window
- included/excluded route prefixes, included/excluded ingress interfaces,
  included/excluded UIDs and UID ranges, and strict address-family routing
- atomic nftables `auto_redirect` for local and forwarded IPv4/IPv6 TCP, UDP
  and ICMP, with interface/MAC/UID/prefix filtering and outbound mark bypass
- hot `route_address_set` / `route_exclude_address_set` CIDR extraction from
  inline, local, remote source and binary SRS rule-sets
- independent UDP NAT mapping/filtering modes, idle expiry, memory-aware
  defaults and bounded LRU eviction
- router forwarding sysctls, Docker `DOCKER-USER` compatibility, stale-state
  recovery (including SIGKILL restart) and exact normal-shutdown cleanup
- isolated client/gateway/server namespace verification for IPv4/IPv6 TCP,
  UDP and ICMP
- transactional setup and exact rollback on normal shutdown, cancellation,
  or partially failed installation

The runtime rejects Android package/user filters, explicit network namespaces,
loopback remapping, the optional NFQUEUE pre-match controls and deprecated
endpoint-independent NAT rather than silently ignoring them. `mixed`, `gvisor` and `smoltcp` select the same
Rust smoltcp data plane; the native `system` stack is not implemented.

### Outbounds

- `direct`
- `block`
- `selector` — a group forwarding to one manually selected member outbound,
  with a `default` member, switchable at runtime by a future Clash API
- `urltest` — a group that periodically probes each member through its dialer
  and auto-selects the fastest within `tolerance`
- `vless` with XHTTP
- `anytls` with TLS, multiplexed session reuse and UDP-over-TCP v2

### AnyTLS

- protocol v2 authentication and all defined frame commands
- client and server operation with sing-box-style configuration
- dynamic padding scheme negotiation
- reusable idle-session pools and cleanup controls
- SYNACK reporting and timeout recovery
- TCP and UDP-over-TCP v2
- routing between AnyTLS, direct and VLESS/XHTTP paths
- multi-user inbound authentication
- client ECH from static configuration or DNS HTTPS records
- server ECH from sing-box ECH key material
- TLS custom roots, certificate/public-key pinning, ALPN, and mutual TLS

### DNS

- UDP
- TCP
- DNS over TLS
- DNS over HTTPS
- local system resolution
- A and AAAA lookup
- UDP truncation fallback to TCP
- one long-lived multiplexed UDP socket per upstream with concurrent
  transaction-ID dispatch
- bounded reusable TCP and DoT connection pools with stale-connection retry
- one prebuilt native-root TLS configuration shared by all DoT pools
- singleflight coalescing for concurrent identical lookups and raw exchanges
- TTL-based lookup and raw-message caching with response TTL aging
- bounded O(1)-amortized LRU eviction and an expiry heap
- per-domain upstream selection by exact domain, suffix, or keyword
- raw DNS message exchange for DNS hijacking

### Routing

Rules are evaluated in declaration order and the first matching rule wins.
Implemented match fields:

- exact domain
- domain suffix
- domain keyword
- domain regular expression
- destination CIDR
- source CIDR
- private destination/source IP
- IP version, exact source/destination port, and port ranges
- network, protocol, sniffed client, inbound tag, and authenticated proxy user
- process name/path/path regex, package name compatibility, user name and UID
- network type/metered state, Wi-Fi SSID/BSSID, interface address maps,
  default-interface addresses, source MAC/hostname, and Clash mode
- rule-set membership
- nested logical `and`/`or`
- inversion

Linux route metadata (process, user, network, interface, MAC and hostname) is
collected lazily: the compiled router reports which fields its rules reference,
and the SOCKS/HTTP inbound skips the `/proc` scan and subprocess probes entirely
when no rule needs them. Interface and default-interface information is cached
for a short TTL, so a per-connection full `/proc` walk is never performed unless
a rule actually matches on those fields.

Implemented actions:

- route to outbound, direct, and bypass
- non-terminal route-options, sniff, and resolve
- reject with reset/drop/reply behavior
- `hijack-dns`

Implemented rule-set sources:

- inline source rules
- local source JSON and binary SRS
- remote source JSON and binary SRS with size limits, cache fallback, and
  periodic atomic refresh

### Configuration and CLI

- sing-box-style JSON input
- `xhttp check -c <config>`
- `xhttp run -c <config>`
- validation of supported inbounds and outbounds
- UUID, TLS/ECH material, XMUX ranges, transport placement, method, route
  reference, DNS reference, and rule-set validation
- configurable logging level and output
- multiple supported inbounds in one process
- `experimental.clash_api` with an `external_controller`, optional `secret`,
  and an optional `external_ui` that auto-downloads the Yacd-meta dashboard.
  The HTTP API exposes `/version`, `/configs` (rule/global/direct mode),
  `/proxies` (selector/urltest groups plus leaf outbounds and a GLOBAL
  selector), node switching, and per-node delay tests, so a Clash dashboard
  can switch nodes and modes against the shared proxy runtime.

## Source map

| File | Responsibility |
| --- | --- |
| `src/config.rs` | Internal XHTTP client/server configuration and validation |
| `src/singbox.rs` | sing-box JSON structures, conversion, and runtime validation |
| `src/protocol.rs` | XHTTP metadata, payload, padding, cookie, and header encoding |
| `src/client.rs` | XHTTP client and h1/h2/h3 upload/download modes |
| `src/xmux.rs` | XHTTP HTTP-client pool selection, reuse, and request budgets |
| `src/server.rs` | XHTTP server, HTTP/3 server, sessions, ordering, and limits |
| `src/vless.rs` | VLESS handshake, TCP, classic UDP, and XUDP |
| `src/proxy/mod.rs` | Proxy runtime, outbound dialer construction, and flow dispatch |
| `src/proxy/relay.rs` | AnyTLS/TUN TCP and UDP relay entry points and first-packet writing |
| `src/proxy/inbound.rs` | SOCKS/HTTP/mixed inbound listener, handshakes, and authentication |
| `src/proxy/route.rs` | Route evaluation, sniffing, and destination override |
| `src/proxy/udp.rs` | SOCKS UDP associate, UDP sessions, DNS relay, and UDP destination mapping |
| `src/proxy/direct.rs` | Direct TCP/UDP connection helpers and Linux socket options |
| `src/dns/mod.rs` | DNS resolver, lookup, exchange, ECH, rule selection, and singleflight |
| `src/dns/cache.rs` | DNS cache entries, LRU/expiry eviction, and flight coordination |
| `src/dns/transport.rs` | DNS UDP multiplexer, TCP/DoT pools, and HTTPS transport |
| `src/dns/message.rs` | DNS message parsing, query building, TTL rewriting, and ECH parsing |
| `src/tun.rs` | Linux TUN device, Tokio packet pumps, smoltcp TCP/UDP lifecycle |
| `src/tun_route_linux.rs` | Transactional Linux auto-route/strict-route policy rules |
| `src/anytls.rs` | AnyTLS TLS setup, sing-box client conversion, and inbound runtime |
| `src/routing.rs` | Rule compilation, rule-set loading, matching, and actions |
| `src/util.rs` | Shared duration/address-string helpers |
| `src/main.rs` | CLI, logging, config loading, and task lifecycle |
| `tests/interop.sh` | sing-box/Xray end-to-end compatibility matrix |
| `fuzz/` | cargo-fuzz targets for six untrusted parser surfaces |
| `tests/load.sh` | repeatable local TCP/UDP load and RSS probe |

## Known boundaries

The following are intentionally not represented as completed features:

### XHTTP/VLESS boundaries

- adaptive `auto` mode selection
- VLESS flow, including Vision
- `packetaddr`
- REALITY
- uTLS/browser ClientHello impersonation
- DNS-discovered ECH and ECH server operation
- mux.cool (`smux`, `yamux`, or `h2mux`); XHTTP XMUX is supported instead
- SOCKS5 UDP fragmentation

### sing-box configuration boundaries

- GeoIP and Geosite databases
- fake-IP DNS
- `preferred_by` outbounds and remote rule-set `download_detour`
- Linux-unavailable constrained-network, TCP multipath, and TLS spoof features
- TLS on local proxy inbounds
- non-XHTTP VLESS transports
- inbound/outbound types other than those listed above

### Operational boundaries

- hot reload
- management API
- metrics endpoint
- persistent DNS cache
- dynamic certificate reload
- privilege dropping/sandbox setup
- system service generation
- production-duration load and soak baselines; the current baseline is a
  short local regression probe
- completed sustained fuzz campaigns and retained corpora; the targets use
  nightly Rust and a C++/libFuzzer toolchain

Unknown sing-box JSON fields may deserialize without affecting execution, but
that does not mean the associated behavior is implemented. Runtime-relevant
features must be explicitly converted, validated, executed, and tested before
being listed as supported.

## Roadmap

### Phase 1: Harden the existing XHTTP/VLESS core

Completed foundations:

- cargo-fuzz targets for VLESS destinations, XUDP frames, SOCKS5 UDP packets,
  DNS messages, cookies, and XHTTP metadata;
- malformed path/authentication/packet tests, orphan session expiry, session
  limits, ordering, and concurrent isolation tests;
- a repeatable TCP/UDP load probe and short memory/request-rate baseline in
  `doc/performance.md`;
- a repeatable release-mode DNS benchmark covering lookup-cache hits,
  raw-message-cache hits, sequential UDP misses, and 64-way UDP concurrency;
- Rust-to-Rust IPv6 packet-up coverage;
- exhaustive unit coverage for all implemented metadata, payload, and padding
  placement combinations;
- TLS untrusted certificate, hostname, and ALPN mismatch checks; and
- exact sing-box and Xray revisions recorded above.

Remaining hardening work:

- run sustained fuzz campaigns and retain/minimize useful corpora;
- expand cancellation, slow peer, disconnect, and resource exhaustion tests;
- test IPv6 with sing-box and Xray in every client/server direction;
- exercise every placement combination against external implementations;
- add expired/not-yet-valid certificate cases; and
- run production-duration load, soak, packet-loss, and reordering campaigns.

Completion criteria:

- no parser panics on fuzzed network input;
- bounded memory under invalid or slow sessions;
- all existing interoperability tests remain green; and
- reproducible performance and resource measurements exist.

### Phase 2: Close high-value compatibility gaps

- Implement VLESS `packetaddr`, including IPv4/IPv6 address-prefix framing and
  SOCKS5 UDP integration.
- Decide whether `auto` should reproduce sing-box selection rules or remain a
  documented deterministic alias.
- Add TLS to local proxy inbounds if real configurations require it.

Each item requires sing-box and/or Xray interoperability tests before it is
marked complete.

### Phase 3: DNS and routing expansion

- Expand DNS rule fields and actions based on real configurations.
- Add missing cache behavior only where it can be specified and tested.
- Evaluate legacy GeoIP/Geosite databases independently from SRS support.
- Extend platform routing only through platform-specific modules and tests.
- Evaluate fake-IP as a separate subsystem rather than a small DNS option.

### Phase 4: Production lifecycle

- Add graceful drain with a bounded shutdown deadline.
- Add configuration reload with atomic validation and rollback.
- Add structured metrics for sessions, requests, bytes, UDP mappings, DNS
  cache, routing decisions, failures, and resource-limit rejections.
- Add dynamic certificate reload.
- Add release packaging and service examples.
- Add long-running soak, packet-loss, reordering, and network migration tests.

### Phase 5: Optional new protocols

ShadowQUIC is an optional future protocol and must not be conflated with
XHTTP. Its JLS handshake modifies the Rustls/Quinn security model and requires
forked networking crates. Keep it feature-gated and isolated from the existing
HTTP/3 stack if implementation proceeds.

The completed protocol and dependency investigation is recorded in:

- `doc/shadowquic-jls-investigation.md`

That document must be reviewed before starting ShadowQUIC/JLS work. In
particular, resolve the listed wire-format ambiguities, 0-RTT replay behavior,
active-probe forwarding risks, and fork maintenance policy first.

## Change discipline

When adding a capability:

1. Add the corresponding typed configuration fields.
2. Reject invalid or unsupported combinations during `check`.
3. Implement both client and server behavior where applicable.
4. Add focused unit/integration tests.
5. Add sing-box/Xray interoperability coverage when an external implementation
   exists.
6. Update `README.md` and this plan so claimed support matches runtime behavior.

Do not mark a sing-box field as supported merely because Serde accepts it.

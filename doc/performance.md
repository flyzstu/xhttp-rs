# Performance and load probe

`tests/load.sh` runs a repeatable local TCP/UDP smoke load through:

```text
load probe -> SOCKS5 -> VLESS/XHTTP packet-up -> Rust server -> local echo
```

Run it with a duration in seconds and TCP concurrency:

```bash
tests/load.sh 10 16
```

The probe reports completed TCP requests, transferred response bytes, UDP
datagrams, errors, elapsed time and the server/client `VmHWM` values from
`/proc`. It builds and runs the release binary. It is deliberately a short,
local regression probe, not a capacity claim or an Internet benchmark.

## Baseline

Recorded 2026-07-23:

- Intel Core i5-10400, 6 cores / 12 threads
- 31 GiB RAM
- Linux 6.19.14 x86_64
- rustc 1.97.1
- 10 seconds, 16 concurrent TCP workers and one UDP worker
- XHTTP `packet-up`, default packet settings

Result:

```text
TCP requests:              3,802
TCP requests/second:       378.55
TCP application MiB/sec:   0.51
UDP packets:               320
UDP packets/second:        31.86
Errors:                    0
Server peak RSS:           14,232 kB
Client peak RSS:           60,412 kB
```

The TCP workload repeatedly downloads the small repository `Cargo.toml`, so
its request rate primarily measures connection/session churn rather than bulk
bandwidth. Longer soak, large-stream throughput, packet-loss, reordering and
network migration baselines remain separate work.

## DNS microbenchmark

`cargo bench --bench dns` runs against an in-process loopback UDP authority.
It measures resolver and transport overhead without Internet latency. The
benchmark uses the same machine and release profile as the load probe above.

Recorded 2026-07-23 after adding UDP multiplexing, TCP/DoT pools,
singleflight, raw-message caching, and bounded TTL/LRU caching:

```text
lookup cache hit            100000 operations in 0.049s: 2,037,027 ops/s,  0.49 us/op
raw exchange cache hit      100000 operations in 0.030s: 3,311,088 ops/s,  0.30 us/op
UDP multiplexed miss         10000 operations in 0.231s:    43,219 ops/s, 23.14 us/op
UDP 64-way concurrent        99968 operations in 0.428s:   233,463 ops/s,  4.28 us/op
```

These are local implementation-throughput numbers, not public-resolver
capacity claims. Real DoH/DoT performance depends on upstream latency, TLS
resumption, packet loss, and server connection policies.

# xhttp-rs 性能基准（v0.2.0 基线）

这是后续开发的性能基线。**每次提交前用同一命令重跑，对比 ops/s**（越高越好）；同一用例的 µs/op（越低越好）是它的倒数。

## 运行环境（基线捕获时）

- CPU: Intel(R) Core(TM) i5-10400 CPU @ 2.90GHz，12 逻辑核
- OS: Fedora Linux 44 (Server Edition)，x86_64
- rustc/cargo: 1.97.1
- 代码: commit `e69e22b`（v0.2.0 优化后基线）
- 日期: 2026-11-19
- 模式: `cargo bench`（release，`--benches`，harness=false）

## 如何运行

```sh
cargo bench --bench protocol
cargo bench --bench vless
cargo bench --bench routing
cargo bench --bench dns
# 一次性：for b in protocol vless routing dns; do cargo bench --bench "$b"; done
```

每个用例先 warmup，再跑 `samples` 组 × `iterations` 次。输出两行：

- 人类可读行：`ops/s`、`µs/op`、`min/p50/p95/p99/max ops/s`、样本数；
- 机器可读行：`BENCH_JSON {...}`，可用 `grep '^BENCH_JSON' | jq` 提取对比。

共用 harness 在 `benches/common/mod.rs`。所有用例调用**真实生产 API**（`xhttp::protocol`/`vless`/`routing::Router`/`dns::DnsResolver`），不是模拟 matcher。DNS 用例用本地 UDP echo 服务器，不依赖公网。

## 基线结果

### protocol codec（benches/protocol.rs）

| 用例 | 迭代 | ops/s | µs/op | p50 ops/s | p95 ops/s | 样本 |
|---|---:|---:|---:|---:|---:|---:|
| add_common_headers | 20,000 | 6,571,182 | 0.152 | 6,541,805 | 6,713,329 | 7 |
| apply_padding | 20,000 | 731,912 | 1.366 | 729,863 | 742,478 | 7 |
| extract_metadata | 20,000 | 5,975,314 | 0.167 | 5,981,391 | 6,102,493 | 7 |
| authorized | 20,000 | 9,674,711 | 0.103 | 9,671,517 | 9,695,545 | 7 |
| put_payload (body) | 20,000 | 16,505,773 | 0.061 | 16,504,047 | 16,523,764 | 7 |
| extract_payload (body) | 20,000 | 17,148,041 | 0.058 | 17,150,467 | 17,157,323 | 7 |
| put_payload (header,4k) | 20,000 | 218,612 | 4.574 | 218,589 | 222,333 | 7 |
| extract_payload (header,4k) | 20,000 | 147,024 | 6.802 | 147,294 | 148,032 | 7 |
| apply_response_padding | 20,000 | 2,480,610 | 0.403 | 2,492,876 | 2,505,598 | 7 |

### vless codec（benches/vless.rs）

| 用例 | 迭代 | ops/s | µs/op | p50 ops/s | p95 ops/s | 样本 |
|---|---:|---:|---:|---:|---:|---:|
| parse_destination (domain) | 20,000 | 34,577,967 | 0.029 | 34,577,728 | 34,694,635 | 7 |
| parse_destination (ipv4) | 20,000 | 61,153,530 | 0.016 | 61,300,991 | 61,310,763 | 7 |
| write_request (domain,TCP) | 20,000 | 9,094,865 | 0.110 | 9,134,618 | 9,172,545 | 7 |
| write_request (ipv4,TCP) | 20,000 | 9,340,683 | 0.107 | 9,502,691 | 9,690,890 | 7 |
| write_request (ipv6,TCP) | 20,000 | 6,876,816 | 0.145 | 6,974,087 | 7,063,890 | 7 |
| write_request (XUDP command) | 20,000 | 10,480,583 | 0.095 | 10,505,901 | 10,523,054 | 7 |
| read_response | 20,000 | 131,616,057 | 0.008 | 131,859,148 | 131,915,680 | 7 |

### routing（真实 Router，benches/routing.rs）

| 用例 | 迭代 | ops/s | µs/op | p50 ops/s | p95 ops/s | 样本 |
|---|---:|---:|---:|---:|---:|---:|
| compile Router (50 rules) | 50 | 24,872 | 40.206 | 24,958 | 25,381 | 7 |
| route domain suffix hit | 50,000 | 5,274,496 | 0.190 | 5,330,244 | 5,342,050 | 7 |
| route domain keyword hit | 50,000 | 14,432,522 | 0.069 | 14,584,918 | 14,598,344 | 7 |
| route ip cidr hit | 50,000 | 12,061,710 | 0.083 | 12,058,927 | 12,127,245 | 7 |
| route port rule hit | 50,000 | 5,175,668 | 0.193 | 5,304,547 | 5,436,745 | 7 |
| route final (no match) | 50,000 | 5,910,517 | 0.169 | 5,947,653 | 5,983,070 | 7 |

### dns resolver（benches/dns.rs）

| 用例 | 迭代 | ops/s | µs/op | p50 ops/s | p95 ops/s | 样本 |
|---|---:|---:|---:|---:|---:|---:|
| lookup cache hit | 100,000 | 1,489,630 | 0.671 | 1,501,886 | 1,511,329 | 7 |
| raw exchange cache hit | 100,000 | 2,017,655 | 0.496 | 2,036,379 | 2,048,700 | 7 |
| UDP multiplexed miss | 10,000 | 47,652 | 20.985 | 47,472 | 48,833 | 5 |
| UDP 64-way concurrent | 100,000 | 212,009 | 4.717 | 211,434 | 225,081 | 7 |

## 对比方法

把重跑的 `BENCH_JSON` 行和本文件的 `ops/s` 对比。建议关注 p50 ops/s（抗噪）。同一台机器、同一 rustc、同样 release 模式下，退化超过 ~10% 才值得怀疑（单次运行有抖动）。跨机器/跨 rustc 的数字不可直接比较。

## 覆盖范围与局限

- 覆盖：协议编解码（XHTTP 头/负载/padding）、VLESS 请求读写、路由规则编译与匹配、DNS 缓存命中/未命中/64 路并发。
- 未覆盖：真实网络吞吐、TUN 数据面、TCP/UDP relay、TLS 握手、AnyTLS 会话建立。这些依赖外部网络/系统能力，不适合做稳定基线；用 `tests/interop.sh` 做正确性验证。
- `apply_padding` 在 `min != max` 时含随机长度，数值有轻微固有抖动；基线取 p50。

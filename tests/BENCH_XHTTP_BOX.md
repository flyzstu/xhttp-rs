# xhttp-box 真实链路基准

`bench_xhttp_box.py` 测的是**已部署的 xhttp-box**（`ansible/sing_box.yml`，镜像
`ghcr.io/flyzstu/xhttp-box:0.3.0`）在真实公网链路上的下载吞吐与首字节时延（TTFB）。
客户端用本仓库的 `xhttp-rs` SOCKS 入站，分别经 XHTTP 和 AnyTLS 出站连到各主机，
下载目标就是每台主机本机 nginx 提供的 `100mb.bin`，因此 server→文件 这一段走本地，
client→server 这一段走公网——正是隧道引入开销的那一段。

## 方案

- **主机**（`ansible/hosts`，均为 origin IP）：`hkg` 183.87.147.66、`iad` 47.251.71.9、
  `sin` 47.236.121.24、`lax` 96.44.174.145、`lax2` 23.251.34.192。
- **对比模式**：
  - `direct` —— 裸链路基线（本机不开隧道）；
  - `xhttp-packet-up` —— xhttp-rs → xhttp-box vless/xhttp；
  - `anytls` —— xhttp-rs → xhttp-box anytls。
  - 部署的 xhttp 入站被 `server.json.j2:52` 写死为 `packet-up`，`stream-one` /
    `stream-up` 连不上，故不纳入基准。
- **路由细节**：域名 `<host>.piccdn.click` 由 Cloudflare 解析（非 origin IP）。基准直接连
  origin IP:443，并把 TLS SNI 设为 `<host>.piccdn.click`，由 nginx stream 的 SNI 分发到
  对应入站（xhttp 18080 / anytls 8443）。
- **TUN 绕行**：本机 xhttp-box 的 `ip rule 32768 lookup 2022` 会把所有流量抓进 tun0；
  基准在测试期间临时加 `ip rule ... lookup main priority 999` 绕过 TUN，`finally` 中删除，
  确保测的是公网链路而不是本机隧道回环。
- **指标**：`curl -r` 下载 20 MB，`%{speed_download}` 取吞吐、`%{time_starttransfer}` 取 TTFB，
  每格跑 3 次取中位数。
- **凭据**：从 `../ansible/sing_box.yml` 经环境变量 `XHTTP_TOKEN` / `ANYTLS_PASSWORD` 读取，
  不写进仓库（本文件与脚本均不含真实凭据）。

运行：

```sh
export XHTTP_TOKEN=$(awk '/xhttp_token:/{print $2}' ../ansible/sing_box.yml)
export ANYTLS_PASSWORD=$(awk '/anytls_password:/{print $2}' ../ansible/sing_box.yml)
XHTTP_BENCH_CLIENT=./target/release/xhttp python3 tests/bench_xhttp_box.py \
  --hosts hkg,iad,sin,lax,lax2 --modes direct,xhttp-packet-up,anytls \
  --size-mb 20 --samples 3 --timeout 60 --json-out results.json
```

## 结果（2026-11-19，客户端 commit `39ec326` 构建的 release）

20 MB × 3 次，MB/s 中位数（越高越好）；TTFB 为中位数秒数（越低越好）。

| 主机 | direct MB/s | xhttp-packet-up MB/s | anytls MB/s | xhttp/direct | anytls/direct |
|---|---:|---:|---:|---:|---:|
| hkg  | 2.13 | 0.92  | 1.71  | 43%  | 80%   |
| iad  | 6.68 | 2.90  | 9.85  | 43%  | 147%  |
| sin  | 3.59 | 2.06  | 2.06  | 57%  | 57%   |
| lax  | 4.21 | 2.59  | 15.89 | 62%  | 377%  |
| lax2 | 1.10 | 1.11  | 1.11  | 101% | 101%  |

| 主机 | direct TTFB | xhttp TTFB | anytls TTFB |
|---|---:|---:|---:|
| hkg  | 1.108 | 2.136 | 0.737 |
| iad  | 0.514 | 0.680 | 0.523 |
| sin  | 0.692 | 0.621 | 0.423 |
| lax  | 0.587 | 0.971 | 0.349 |
| lax2 | 0.466 | 0.498 | 0.306 |

### 解释与注意事项

- **xhttp-packet-up 普遍比 direct 慢**（hkg/iad 仅 43%，lax2 持平）：XHTTP 基于 HTTP
  长轮询转发 TCP，每段下载要经请求/响应封装，吞吐损耗明显，且 TTFB 普遍升高（hkg 1.1s→2.1s）。
- **anytls 波动极大**（iad 9.85、lax 15.89，但 hkg 1.71、sin/lax2 约 2）：AnyTLS 用空闲
  连接池 + 多路复用，命中预热连接时吞吐可超过 direct（连接复用省去反复握手），未命中或链路
  抖动时回落到链路本身。iad/lax 样本内波动也大（iad 4.98–11.43、lax 6.83–17.06），说明
  跨境链路本身不稳定，3 次采样的中位数只能反映量级，不是精确 SLA。
- **lax2 三模式都在 1.1 MB/s**：该主机链路就是瓶颈，隧道开销被淹没，三模式无差异。
- **direct 基线同样抖动**（iad 3.11–6.82、lax 2.76–5.86）：跨境公网带宽随时刻变化，
   tunnel/direct 比值应看作量级比较，不是严格受控实验。

## 对照：本机 xhttp-rs server（同法测试）

按用户要求，在本地起一个 xhttp-rs 进程跑同样的对比，用来看**纯隧道开销**（无公网链路
噪声）。配置：本机 `xhttp-rs` server 同时开 xhttp :18080 / anytls :18443（自签证书），
本机 range-capable HTTP 文件服务 :18180 提供 100 MB 文件；`xhttp-rs` client 经各自 SOCKS
入站连到本机 server，下载 20 MB × 3 次取中位数。全部走 127.0.0.1，绕开 TUN。

| 模式 | 吞吐中位数 | 相对 direct |
|---|---:|---:|
| direct（无代理） | 3189 MB/s | 100% |
| xhttp-packet-up | 282 MB/s  | 8.8%  |
| anytls          | 657 MB/s  | 20.6% |

**重要前提**：xhttp server 的 `h1_max_pending_bytes` 必须调大（实测设为 64 MiB）。默认
2 MiB 时，下载在 ~2 MiB 处停住（curl 超时只收到 2097099 字节）——这是该参数的背压上限，
不是死锁；调大后 8 MB 下载立刻恢复到 137 MB/s。因此**真实链路基准里 xhttp 远低于
direct，除公网开销外，默认 2 MiB 背压窗口也是重要因素**（每次 GET 只能预取 2 MiB，
受限于 ACK 往返）。

本机对照与真实链路的比值不能直接相减：本机 direct 是内存级 3.2 GB/s，隧道在如此高的基线
下占比自然很小；真实链路 direct 只有 1–7 MB/s，隧道封装与握手开销占比被放大。但两者一致地
显示：**xhttp 的开销显著大于 anytls**（本机 8.8% vs 20.6%，真实链路 43–62% vs 波动 57–377%）。

## 客户端旋钮 A/B（upload 方向，5 主机）

用户列出的 4 个「现在就能调」的客户端旋钮里，只有 3 个真正可由客户端调优：

| 旋钮 | native 字段（config.rs） | sing-box 字段（singbox.rs 映射） | 能否调 |
|---|---|---|---|
| packet interval | `packet_interval_ms` | `sc_min_posts_interval_ms` | 可：30ms → 0 |
| 单次 POST 大小 | `max_packet_size` | `sc_max_each_post_bytes` | **不可**：Go server `scMaxPost=1e6`，超过即 HTTP 400；默认 1e6 已是硬上限 |
| H1 合并延迟 | `h1_coalesce_delay_ms` | `h1_coalesce_delay_ms` | 可：0 → 10ms（上限 1000ms） |
| xmux 连接数 | `xmux.max_connections` | `xmux.max_connections` | 可：0 → 4 |

这些旋钮全部作用于 **upload 路径**（client.rs 的 packet_upload sleep / 合并 / 连接池），
download 的 Go server 根本不读 x-dl-ack，所以只在 download 上测不出效果。因此本轮在 harness
里新增 `upload-<mode>` 与 `+tuned` 变体：在 origin 主机临时起 discard receiver（端口 18190），
客户端经 SOCKS 上传 5 MB × 2 次取中位数；`+tuned` 应用 packet_interval_ms=0、
h1_coalesce_delay_ms=10、xmux.max_connections=4。为避免链路抖动误判，per host 内基线/tuned
交替执行。原始数据：`tests/bench_xhttp_box_results_upload_ab.json`。

旋钮确实生效的诊断：`sc_max_each_post_bytes=8192` + interval=200ms 时 5 MB 上传 90s 超时
（0 字节），而默认 0.24 MB/s；`h1_coalesce_delay_ms=5000` 被 `xhttp check` 拒绝
（must not exceed 1000ms）。证明字段被解析并应用，而非被静默忽略。

| 主机 | upload-direct | xhttp 基线 | xhttp tuned | tuned/基线 |
|---|---:|---:|---:|---:|
| hkg | 1.02 | 0.10 | 0.11 | +10% |
| iad | 2.01 | 0.21 | 0.25 | +19% |
| sin | 1.85 | 0.23 | 0.27 | +17% |
| lax | 1.86 | 0.24 | 0.24 | 0% |
| lax2 | 0.89 | 0.38 | 0.38 | 0% |

**结论（如实）**：tuned 相对基线在 hkg/iad/sin 有 +10~19% 的小幅提升，lax/lax2 无差异；
但样本的标准差极小（如 sin 基线 [0.22,0.23]、tuned [0.27,0.27]），提升方向一致。原因是
1e6 字节分块下 5 MB 只有 ~5 个 POST，30ms 间隔本就微乎其微；旋钮真正受益的是小包高频
场景（诊断里把块降到 8192 字节后影响被放大到超时）。因此这 3 个旋钮是**廉价但有限的优化**：
对大块 bulk 上传只有个位数到十几个百分点的收益，值得保留为默认值，但不要期待数量级改善。
第 4 个旋钮（POST 大小）受 Go server 硬限制，客户端无法单方面提高。

另一个不变的观察：tunneled upload 普遍只有 direct 的 10~40%（hkg 0.10 vs 1.02，iad 0.21
vs 2.01），瓶颈在跨域链路的不对称上行 + XHTTP 请求/响应往返，不在这些旋钮。

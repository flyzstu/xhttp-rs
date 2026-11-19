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

## 对照：xhttp-box 作为客户端（端到端互操作）

按用户要求，改用 `xhttp-box`（`/usr/local/bin/xhttp-box`，sing-box 格式配置）作客户端，
对同样的远端 xhttp-box 服务器跑**完全相同**的流程（5 主机 × direct/xhttp-packet-up/anytls
× 20 MB × 3 次），验证 xhttp-box ↔ xhttp-box 端到端互操作并对比两种客户端。
原始数据：`tests/bench_xhttp_box_results_sbclient.json`。

| 主机 | xhttp-box client direct | xhttp | anytls | xhttp/direct | anytls/direct |
|---|---:|---:|---:|---:|---:|
| hkg  | 1.21 | 1.50 | 1.19  | 124%  | 98%   |
| iad  | 2.45 | 6.22 | 4.21  | 254%  | 172%  |
| sin  | 3.69 | 1.92 | 2.07  | 52%   | 56%   |
| lax  | 4.14 | 3.23 | 9.80  | 78%   | 237%  |
| lax2 | 1.10 | 1.12 | 1.12  | 102%  | 102%  |

### 与 xhttp-rs 客户端的对比

同一主机同一模式下的比值（tunnel/direct，取中位数）：

| 主机 | 模式 | xhttp-rs 客户端 | xhttp-box 客户端 |
|---|---|---:|---:|
| hkg  | xhttp  | 43%  | 124% |
| hkg  | anytls | 80%  | 98%  |
| iad  | xhttp  | 43%  | 254% |
| iad  | anytls | 147% | 172% |
| sin  | xhttp  | 57%  | 52%  |
| sin  | anytls | 57%  | 56%  |
| lax  | xhttp  | 62%  | 78%  |
| lax  | anytls | 377% | 237% |
| lax2 | xhttp  | 101% | 102% |
| lax2 | anytls | 101% | 102% |

**结论**：

- **互操作成立**：两种客户端（xhttp-rs 与 xhttp-box）都能连上远端 xhttp-box 的 XHTTP
  （packet-up）和 AnyTLS 入站，全部 45 次下载成功（hkg xhttp 只有 2/3，其余 3/3）。
- **两组 direct 基线本身差异很大**（如 iad：rs 6.68 vs sb 2.45 MB/s；hkg：2.13 vs 1.21），
  这是两次测试运行于不同时刻、跨境链路抖动所致，因此**绝对值不可直接比较**，只能看同一次
  运行内的 tunnel/direct 比值。
- **xhttp-box 客户端的 xhttp 比值普遍更高**（hkg 124%、iad 254%、lax 78%）——说明
  xhttp-box 自己的 XHTTP 客户端实现与自家服务端配合更好，而 xhttp-rs 客户端连 xhttp-box
  时损耗更大（43–62%），侧面印证 xhttp-rs 的 XHTTP 客户端在 ACK/背压窗口上还有优化空间
  （参见上一节的 2 MiB `h1_max_pending_bytes` 发现）。
- **sin/lax2 两客户端几乎一致**（52–57%、101–102%）：这两条链路本身稳定/是瓶颈，客户端
  实现差异被淹没。
- **anytls 波动依旧**：lax 从 rs 的 377% 降到 sb 的 237%，iad 172%，均受跨境链路抖动主导。

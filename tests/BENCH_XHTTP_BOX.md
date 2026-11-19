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

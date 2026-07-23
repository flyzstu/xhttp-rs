# ShadowQUIC / JLS 调查与后续实现备忘录

更新时间：2026-07-23

本文记录 ShadowQUIC、JLS 以及相关 Rustls/Quinn fork 的调查结果，供
`xhttp-rs` 后续增加 ShadowQUIC 支持时使用。本文不是已经完成的功能说明。

## 1. 调查对象与版本

- ShadowQUIC: <https://github.com/spongebob888/shadowquic>
  - 调查时 `main` HEAD: `6466c8ae681644d4e5f7ce21bb42fb8a4512bc61`
- 协议说明:
  <https://github.com/spongebob888/shadowquic/blob/main/PROTOCOL.typ>
- `rustls-jls`: `1.3.3`
  - <https://github.com/spongebob888/rustls-jls>
- `quinn-jls`: `0.3.6`
  - <https://github.com/spongebob888/quinn-jls>
- `quinn-proto-jls`: `0.3.6`

注意存在两个无关的 JLS 项目：

- ShadowQUIC 使用的是 JimmyHuang454 的 TLS-like JLS：
  <https://github.com/JimmyHuang454/JLS>
- `jetperch/jls` 是 Joulescope 时序数据文件格式，与 ShadowQUIC 和 TLS
  无关：<https://github.com/jetperch/jls>

## 2. ShadowQUIC 的定位

ShadowQUIC 是独立的 TCP/UDP 代理协议，不是 Shadowsocks 插件，也不是
VLESS/XHTTP 的一种模式。其定位接近 TUIC/Hysteria：

```text
SOCKS / HTTP / TProxy
        |
        v
ShadowQUIC 代理命令和 UDP 编码
        |
        v
QUIC streams / QUIC datagrams
        |
        v
JLS 认证和 SNI 伪装
        |
        v
UDP/IP
```

项目声明的主要能力包括：

- QUIC 和可选 0-RTT；
- TCP 和 UDP 代理；
- Full Cone UDP；
- UDP over QUIC Datagram 或 UDP over QUIC unidirectional stream；
- 用户名/密码认证；
- 无自有证书的 SNI 伪装；
- 主动探测流量转发到真实的 `jls-upstream`；
- BBR、Cubic、New Reno，项目层还可接入 Brutal；
- 客户端地址迁移、MTU 探测、GSO 和连接统计。

## 3. ShadowQUIC 应用层协议

每个代理请求由客户端新建一条 QUIC 双向流，并以一字节 `CMD` 开头。

| CMD | 含义 |
| --- | --- |
| `0x01` | TCP Connect |
| `0x03` | UDP Association over QUIC Datagram |
| `0x04` | UDP Association over QUIC unidirectional stream |
| `0x05` | SunnyQUIC authentication |
| `0xff` | 自定义扩展 |

### 3.1 SOCKSADDR

协议复用 SOCKS 地址格式：

```text
ATYP(1) | ADDR(variable) | PORT(2, network byte order)
```

- `0x01`: IPv4；
- `0x03`: 域名；
- `0x04`: IPv6。

### 3.2 TCP

TCP Connect 流的格式为：

```text
CMD(0x01) | SOCKSADDR | TCP byte stream
```

一个 TCP 代理连接对应一条 QUIC 双向流。

### 3.3 UDP

UDP Association 首先建立一条保持存活的双向控制流。控制流传输地址与两字节
Context ID 的映射，不传输 UDP payload：

```text
控制流:
CMD(0x03/0x04) | bind SOCKSADDR
SOCKSADDR(A) | CONTEXT_ID(1)
SOCKSADDR(B) | CONTEXT_ID(2)
...
```

客户端到服务端、服务端到客户端分别维护独立的 Context ID 空间。控制流关闭时，
整个 UDP association 必须关闭。

使用 QUIC Datagram 时：

```text
CONTEXT_ID(2) | UDP PAYLOAD
```

使用 QUIC unidirectional stream 时：

```text
CONTEXT_ID(2) | LEN(2) | PAYLOAD | LEN(2) | PAYLOAD | ...
```

同一条 unidirectional stream 只在开头发送一次 Context ID，后续可连续发送同一
Context ID 的报文。地址映射至少在新 Context ID 首次使用时通过控制流发送一次。

这个设计将常见 UDP 数据包的额外头部压缩到两字节，同时允许一个 association
访问多个目标。实现时必须保留 UDP datagram 边界。

## 4. JLS 握手和安全模型

ShadowQUIC 的协议文档声明代理命令层不单独认证；认证由 JLS 握手层完成。
`rustls-jls` 的实际实现将用户名/密码认证编码到 TLS 1.3
`ClientHello.random` 和 `ServerHello.random`。

### 4.1 ClientHello 认证

根据 `rustls-jls 1.3.3` 源码，客户端大致执行：

```text
auth_data = ClientHello 编码（random 清零，PSK binder 清零）
key       = SHA256(password || auth_data)
nonce     = SHA256(username || auth_data)

ClientHello.random =
    AES-256-GCM(key, nonce, random_16_bytes)
```

AES-GCM 对 16 字节明文输出 16 字节密文和 16 字节 tag，结果正好占据 32
字节 Random 字段。

服务端遍历配置用户，使用各用户的 username/password 尝试验证该字段，并同时校验
ClientHello SNI 是否符合配置。服务端在 `ServerHello.random` 中执行对称的认证，
使客户端验证服务端也持有共享凭据。

代码入口：

- <https://github.com/spongebob888/rustls-jls/blob/jls-main/rustls/src/jls/mod.rs>
- <https://github.com/spongebob888/rustls-jls/blob/jls-main/rustls/src/server/jls.rs>
- <https://github.com/spongebob888/rustls-jls/blob/jls-main/rustls/src/client/tls13.rs>
- <https://github.com/spongebob888/rustls-jls/blob/jls-main/rustls/src/server/tls13.rs>

### 4.2 证书模型

JLS 认证成功后，`rustls-jls` 会跳过常规服务器证书链和 TLS 1.3
CertificateVerify 验证，以共享 username/password 完成对端身份认证。因此它不是
标准 PKI TLS 的同一种信任模型，也不能将普通 Rustls 与 JLS 直接互换。

密码必须具有足够的随机熵，不能把容易猜测的人类密码视为与高强度私钥等价。

### 4.3 主动探测转发

服务端配置真实 QUIC/HTTP3 上游，例如：

```yaml
jls-upstream:
  addr: "cloudflare.com:443"
server-name: "cloudflare.com"
alpn: ["h3"]
```

收到的 ClientHello 若通过 JLS 认证，则建立 ShadowQUIC 连接；若认证失败且配置了
上游，则相关 QUIC UDP 数据包被转发到真实上游，上游响应再转回原客户端：

```text
普通 QUIC 探测者
       |
       v
ShadowQUIC server
       |
       v
真实 QUIC/HTTP3 upstream
```

这部分转发不是 Rustls 自己完成的，而由 `quinn-proto-jls` 产生状态/事件，再由
`quinn-jls` 执行 socket I/O。

### 4.4 0-RTT

ShadowQUIC 默认可启用 0-RTT。后续实现必须明确处理 TLS/QUIC 0-RTT 的重放风险：

- 不应在可重放的 early data 中执行用户管理等不可幂等操作；
- TCP/UDP 建连命令被重放时的资源和副作用需要测试；
- 服务端应限制 replay、并发和资源占用。

## 5. 三个 fork 相比原版的差异

### 5.1 rustls-jls

基线为 Rustls 0.23.x（fork 历史包含 `v/0.23.36`），主要增加：

- `JlsClientConfig`、`JlsServerConfig` 和 `JlsUser`；
- JLS 开关、用户列表、伪装上游、SNI 和转发限速配置；
- `AuthSuccess`、`AuthFailed`、`NotAuthed`、`Disabled` 状态；
- ClientHello/ServerHello Random 字段认证；
- JLS 成功后的证书验证旁路；
- JLS 与 QUIC 适配所需的认证状态和用户查询接口；
- HelloRetryRequest、PSK binder 和 0-RTT 的额外处理。

该 fork 仍保留关闭 JLS 后执行普通 TLS 的路径，但开启 JLS 后不再是普通 Rustls
身份认证语义。

### 5.2 quinn-proto-jls

`quinn-proto` 是不执行 socket I/O 的 QUIC 状态机。fork 主要增加：

- crypto trait 中的 `is_jls()`、`is_jls_enabled()`、
  `jls_upstream_addr()`、`jls_chosen_user()`；
- 从 `rustls-jls` 读取认证结果；
- `JlsAuthFailed` 和 `JlsForwardError`；
- JLS 认证失败时保留原始 QUIC Initial 数据；
- 生成将失败流量转发到伪装上游的事件；
- 客户端迁移期间的 JLS 上游迁移事件；
- JLS 所需的连接统计、MTU 和拥塞控制接口改动。

重要限制：当前实现注释指出，JLS ClientHello 需要完整落在第一个 QUIC Initial
packet 中，否则可能被当作需要转发的失败连接。后续互操作和异常分片测试必须覆盖
这一点。

### 5.3 quinn-jls

`quinn` 是异步 socket/runtime 层。fork 主要增加：

- 消费 `quinn-proto-jls` 的 JLS 认证和转发事件；
- 为每个探测客户端建立到 `jls-upstream` 的 UDP socket；
- 双向转发原始 QUIC datagram；
- 转发限速和空闲连接状态；
- NAT rebinding/QUIC migration 期间的映射维护；
- `Connection::is_jls()` 和 `Connection::jls_chosen_user()`；
- 配套的 `quinn-udp-jls` 依赖。

核心转发实现：
<https://github.com/spongebob888/quinn-jls/blob/jls-main/quinn/src/jls.rs>

### 5.4 依赖关系

这三个组件需要成套使用：

```text
quinn-jls
    |
    +-- quinn-proto-jls
    |       |
    |       +-- rustls-jls
    |
    +-- quinn-udp-jls
```

仅将原版 `rustls` 替换成 `rustls-jls`，不能获得认证失败流量转发和完整
ShadowQUIC 服务端行为。

## 6. SunnyQUIC

同一份协议还定义 SunnyQUIC。它复用 ShadowQUIC 的 TCP/UDP 应用层帧，但放弃
JLS，使用原生 QUIC/TLS，并通过 `CMD 0x05` 在 QUIC 双向流内认证。

协议文档当前写作：

```text
CMD(1) | AUTH_HASH(64)
AUTH_HASH = SHA256(username:password)[0..64]
```

这里存在需要确认的规格歧义：SHA-256 原始输出只有 32 字节，“64”可能指 64 字符
十六进制编码，也可能是文档长度错误。实现 SunnyQUIC 前必须以多个现有客户端的
互操作结果确认，不能仅按该文字实现。

SunnyQUIC 与 ShadowQUIC 的应用层可共享，但握手、认证和伪装策略应作为不同后端。

## 7. 与 xhttp-rs 当前依赖的关系

`xhttp-rs` 当前已经使用：

- `rustls 0.23`
- `quinn 0.11`
- `h3`
- `h3-quinn`

ShadowQUIC 使用 package rename 后的 fork：

- `rustls-jls 1.3.3`
- `quinn-jls 0.3.6`
- `quinn-proto-jls 0.3.6`

Cargo 可以同时解析不同 package name，但两套 crate 的 Rust 类型不兼容。例如原版
`rustls::ServerConfig` 不能直接传给 `quinn-jls`，`quinn::Connection` 也不同于
`quinn-jls` 的 Connection。

为了避免影响现有 XHTTP HTTP/3 路径，后续实现不应立即用 fork 全局替换原版
Rustls/Quinn。建议先隔离为可选功能：

```toml
[features]
shadowquic = [
  "dep:rustls-jls",
  "dep:quinn-jls",
  "dep:quinn-proto-jls"
]
```

并将 ShadowQUIC 相关类型限制在独立模块中。

## 8. 建议实现边界

第一阶段目标应是最小、可互操作的 ShadowQUIC inbound/outbound：

1. 新增配置类型，不改变现有 VLESS/XHTTP 配置行为；
2. 先支持 TCP Connect；
3. 支持 UDP over QUIC Datagram；
4. 再支持 UDP over unidirectional stream；
5. 接入现有 SOCKS/mixed inbound 和 direct outbound；
6. 支持 JLS 用户名/密码、SNI、ALPN 和 upstream；
7. 支持 0-RTT 开关，默认值需要经过安全评估；
8. 实现会话数、流数、datagram 大小和空闲时间限制；
9. 最后考虑 TProxy、Brutal、用户管理和统计 API。

建议模块边界：

```text
src/shadowquic/
    mod.rs
    config.rs
    client.rs
    server.rs
    command.rs
    udp.rs
```

`command.rs` 负责 CMD 和 SOCKSADDR；`udp.rs` 负责 Context ID、控制流和
datagram/unistream framing。JLS/Quinn 类型只出现在 `client.rs` 和 `server.rs`。

## 9. 实现策略选择

### 方案 A：直接依赖 fork

优点：

- 最快达到现有客户端互操作；
- 复用 JLS 握手、失败流量转发和迁移处理；
- 与 ShadowQUIC 主项目的行为更接近。

缺点：

- 引入安全敏感 fork；
- 与现有原版 Rustls/Quinn 重复，增加二进制和编译体积；
- fork API、版本号和上游同步策略不稳定；
- 安全更新需要同时追踪原版和 fork。

### 方案 B：在原版 Rustls/Quinn 上重做 JLS

优点：

- 能控制改动范围和代码质量；
- 可减少长期 fork 依赖。

缺点：

- Rustls 公共 API 不足以实现所有握手改写，可能仍需维护 fork；
- Quinn 原版不暴露所需的 Initial 原始包转发状态；
- 工作量和互操作风险显著更高。

当前建议先采用方案 A，通过 Cargo feature 和模块边界隔离。完成互操作、模糊测试
和安全审查后，再决定是否收敛 fork。

## 10. 验证计划

必须建立独立互操作矩阵：

| 方向 | TCP | UDP Datagram | UDP Stream | 0-RTT |
| --- | --- | --- | --- | --- |
| xhttp-rs client -> ShadowQUIC server | 必测 | 必测 | 必测 | 必测 |
| ShadowQUIC client -> xhttp-rs server | 必测 | 必测 | 必测 | 必测 |
| mihomo/husi -> xhttp-rs server | 必测 | 必测 | 视支持情况 | 必测 |
| xhttp-rs client -> mihomo server | 必测 | 必测 | 视支持情况 | 必测 |

还需要覆盖：

- IPv4、IPv6、域名 SOCKSADDR；
- 多 TCP stream 并发；
- 一个 UDP association 多目标；
- 双向 Context ID 空间；
- Context ID 重用、乱序、丢包和重复包；
- 控制流提前关闭；
- 大 datagram、MTU 变化和 IP 分片边界；
- NAT rebinding/connection migration；
- 错误用户名、密码、SNI 和 ALPN；
- 主动探测转发以及 upstream 不可用；
- ClientHello 跨 Initial packet；
- 0-RTT 重放；
- 用户和连接资源耗尽；
- fuzz CMD、SOCKSADDR、Context ID 和 length decoder。

## 11. 开始编码前仍需确认

- ShadowQUIC 协议是否有版本协商或事实上的版本字段；
- 现有实现对未知 CMD、重复 Context ID 和地址重绑定的准确行为；
- SunnyQUIC `AUTH_HASH(64)` 的实际线格式；
- JLS 在 HelloRetryRequest、QUIC Retry、PSK 恢复和 0-RTT 下的完整互操作行为；
- ClientHello 未完整落入首个 Initial 时，各实现如何处理；
- JLS upstream 转发是否会形成放大、反射或未授权中继风险；
- fork 对原版 Rustls/Quinn 安全修复的同步延迟；
- `rustls-jls` 跳过证书验证后的威胁模型和密码强度要求；
- mihomo、husi、clash-rs 当前各自实现采用的协议细节。

在以上问题确认前，不应将 ShadowQUIC 标为生产稳定功能。

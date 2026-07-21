# P2WLAN 协议与状态机草案

Version: 0.1  
Date: 2026-07-16

## 1. 设计原则

- 数据面端到端加密，控制面和 Relay 不解密用户流量。
- 设备身份基于公钥，虚拟 IP 是可变配置，不作为安全身份。
- P2P direct path 优先，Relay path 兜底。
- 协议消息用 protobuf 定义，传输可先使用 gRPC stream，后续可切换 QUIC。
- 第一版不追求完整 ICE 规范，先实现候选地址收集、信令交换、并发 probe、路径选择和 fallback。

## 2. 身份模型

每个设备持有两类密钥：

| 密钥 | 用途 | 生命周期 |
| --- | --- | --- |
| Device Identity Key | 控制面身份、签名、设备注册 | 长期 |
| WireGuard Key Pair | 数据面加密隧道 | 长期或可轮换 |

设备标识：

```text
device_id = base32(blake3(device_identity_public_key))[0..32]
wg_peer_id = base64(wireguard_public_key)
```

控制面必须维护 device identity public key 与 WireGuard public key 的绑定关系。

## 3. 地址模型

虚拟网络：

```text
IPv4 CIDR: 10.20.0.0/16
IPv6 CIDR: fd20::/64
```

设备配置：

```text
device_id: dev_abc
virtual_ipv4: 10.20.0.2
virtual_ipv6: fd20::2
allowed_ips:
  - 10.20.0.2/32
  - fd20::2/128
```

候选地址：

```text
host candidate: 192.168.1.10:41641
srflx candidate: 203.0.113.10:53001
relay candidate: relay-cn-shanghai-1/dev_abc
```

## 4. Protobuf 草案

建议目录：

```text
proto/p2wlan/v1/control.proto
proto/p2wlan/v1/signaling.proto
proto/p2wlan/v1/relay.proto
```

### control.proto

```proto
syntax = "proto3";

package p2wlan.v1;

message Device {
  string id = 1;
  string name = 2;
  string user_id = 3;
  string network_id = 4;
  string identity_public_key = 5;
  string wireguard_public_key = 6;
  string virtual_ipv4 = 7;
  string virtual_ipv6 = 8;
  string os = 9;
  string version = 10;
}

message PeerConfig {
  string device_id = 1;
  string wireguard_public_key = 2;
  repeated string allowed_ips = 3;
  repeated Endpoint endpoints = 4;
  repeated string relay_regions = 5;
  repeated AclRule acl_rules = 6;
}

message Endpoint {
  string ip = 1;
  uint32 port = 2;
  EndpointType type = 3;
  uint32 priority = 4;
}

enum EndpointType {
  ENDPOINT_TYPE_UNSPECIFIED = 0;
  ENDPOINT_TYPE_HOST = 1;
  ENDPOINT_TYPE_SERVER_REFLEXIVE = 2;
  ENDPOINT_TYPE_RELAY = 3;
}

message AclRule {
  string id = 1;
  string source = 2;
  string destination = 3;
  string protocol = 4;
  string port_range = 5;
  string action = 6;
  uint32 priority = 7;
}

service ControlService {
  rpc RegisterDevice(RegisterDeviceRequest) returns (RegisterDeviceResponse);
  rpc GetNetworkMap(GetNetworkMapRequest) returns (GetNetworkMapResponse);
  rpc WatchNetworkMap(WatchNetworkMapRequest) returns (stream NetworkMapEvent);
  rpc Heartbeat(HeartbeatRequest) returns (HeartbeatResponse);
}
```

### signaling.proto

```proto
syntax = "proto3";

package p2wlan.v1;

message Candidate {
  string device_id = 1;
  string ip = 2;
  uint32 port = 3;
  CandidateType type = 4;
  string protocol = 5;
  uint32 priority = 6;
  int64 observed_at_unix_ms = 7;
}

enum CandidateType {
  CANDIDATE_TYPE_UNSPECIFIED = 0;
  CANDIDATE_TYPE_HOST = 1;
  CANDIDATE_TYPE_SERVER_REFLEXIVE = 2;
  CANDIDATE_TYPE_RELAY = 3;
}

message SignalEnvelope {
  string from_device_id = 1;
  string to_device_id = 2;
  string message_id = 3;
  int64 created_at_unix_ms = 4;
  bytes signed_payload = 5;
}

message PunchRequest {
  string session_id = 1;
  repeated Candidate candidates = 2;
  bytes nonce = 3;
}

message PunchAck {
  string session_id = 1;
  repeated Candidate candidates = 2;
  bytes nonce = 3;
}

service SignalingService {
  rpc OpenSignalStream(OpenSignalStreamRequest) returns (stream SignalEnvelope);
  rpc SendSignal(SignalEnvelope) returns (SendSignalResponse);
}
```

### relay.proto

```proto
syntax = "proto3";

package p2wlan.v1;

message RelayFrame {
  string src_device_id = 1;
  string dst_device_id = 2;
  uint64 seq = 3;
  bytes encrypted_payload = 4;
}

message RelayRegisterRequest {
  string device_id = 1;
  string identity_public_key = 2;
  bytes signature = 3;
}

message RelayServerInfo {
  string id = 1;
  string region = 2;
  string url = 3;
  uint32 priority = 4;
}

service RelayService {
  rpc Register(RelayRegisterRequest) returns (RelayRegisterResponse);
  rpc OpenRelayStream(stream RelayFrame) returns (stream RelayFrame);
}
```

## 5. NAT 穿透状态机

### PeerConnectionState

```text
Idle
  -> NeedPeerConfig
  -> GatheringCandidates
  -> SignalingCandidates
  -> Probing
  -> DirectReady
  -> RelayReady
  -> Failed
```

### 状态说明

| 状态 | 说明 | 超时 |
| --- | --- | --- |
| NeedPeerConfig | 等待控制面下发 peer 信息 | 10s |
| GatheringCandidates | 收集 host/srflx/relay candidate | 2s |
| SignalingCandidates | 交换候选地址 | 3s |
| Probing | 两端并发发送 UDP probe | 5s |
| DirectReady | 直连可用，WireGuard endpoint 指向 direct endpoint | 持续保活 |
| RelayReady | Relay 可用，WireGuard endpoint 指向 Relay transport | 持续保活 |
| Failed | direct 和 Relay 都不可用 | 指数退避 |

## 6. Probe Packet

Probe packet 不承载用户数据，只用于路径发现。

### 6.1 Legacy Probe v1

v1 是历史兼容格式，仍用于没有 Probe v2 MAC key 的 peer。

```text
u8[4] magic       "PNCH"
u8    version     1
u8    msg_type    1=PUNCH, 2=ACK
u8[8] nonce       random correlation nonce
```

约束：

- v1 ACK 只有在来源地址匹配已知 candidate 或已知 endpoint 时才会更新直连状态。
- v1 包不能学习未上报的 peer-reflexive endpoint。
- v1 不承载身份，不能作为最终安全边界。

### 6.2 Authenticated Probe v2 Skeleton

v2 与 v1 共存。daemon 在能通过本机 X25519 private key 与 peer X25519 public key 派生 Probe MAC key 时优先发送 v2，否则回退 v1。

当前 skeleton wire layout：

```text
u8[4] magic          "PNCH"
u8    version        2
u8    msg_type       1=PUNCH, 2=ACK
u8[8] nonce          random correlation nonce
u64   generation     sender local network generation, big-endian
u8    src_len        1..255
u8    dst_len        1..255
u8[]  src_node_id    UTF-8, src_len bytes
u8[]  dst_node_id    UTF-8, dst_len bytes
u8[16] mac           truncated HMAC-BLAKE2s
```

MAC 输入：

```text
mac = HMAC_BLAKE2s_256(
  probe_mac_key,
  "p2wlan-udp-probe-v2" || frame_without_mac
)[0..16]
```

当前 daemon 派生：

```text
shared = X25519(local_node_private_key, peer_public_key)
probe_mac_key = HMAC_BLAKE2s_256(shared, "p2wlan udp probe v2 mac key")
```

接收规则：

- `dst_node_id` 必须等于本机已解析 node ID，否则丢弃。
- peer 必须已知且存在可派生的 Probe MAC key，否则丢弃。
- MAC 验证失败、格式错误或空 node ID 直接丢弃，不转发给 WireGuard inbound。
- v2 PUNCH 验证通过后可以学习来源 UDP 地址，即使该地址不在控制面 candidate 列表中。
- v2 ACK 必须匹配 pending nonce、peer ID 和本地 network generation；验证通过后可以确认来源地址为 direct endpoint。
- legacy v1 仍保持原兼容行为；v2 不改变控制面 candidate wire format。

消息类型：

| msg_type | 名称 | 方向 |
| --- | --- | --- |
| 1 | PUNCH | A -> B |
| 2 | ACK | B -> A |

后续 A3 目标：改为 session-bound 临时 X25519 key、显式 session ID、nonce replay window、限速预算和跨语言 golden vectors。当前 v2 skeleton 的目标是先阻止伪造 ACK 改写路径状态，并为 peer-reflexive endpoint 学习提供认证基础。

## 7. 路径选择

候选路径评分：

```text
score = type_weight + rtt_weight + success_history_weight + relay_penalty
```

默认优先级：

1. host candidate，同局域网。
2. server-reflexive candidate，公网 UDP 打洞。
3. peer relay candidate。
4. public Relay server。

路径切换原则：

- direct 成功后立即优先 direct。
- direct 连续 keepalive 失败 3 次，切到 Relay。
- Relay 工作期间每 30s 重新尝试 direct。
- 网络接口变化时立即重新 gather candidates。

Relay region 选择：

- 客户端候选使用 `region@endpoint`，旧 `endpoint` 格式归入 `default` region。
- 候选并发完成 TCP 连接和 relay 注册，单候选受 selection timeout 限制。
- 排序键依次为配置的 region 偏好、连接与注册耗时、控制面候选顺序。
- 首选候选失败时保留错误诊断并选择下一个可达候选。
- relay 注册必须使用控制面分配的 node ID，确保 peer 转发目标与 relay session 身份一致。
- 当前 relay 节点之间没有 mesh 转发；控制面必须向同一虚拟网络下发一致候选列表，跨 region 互联属于后续协议扩展。

## 8. WireGuard Endpoint 管理

WireGuard peer endpoint 由路径管理器更新：

```text
DirectReady:
  peer endpoint = remote_srflx_ip:remote_srflx_port

RelayReady:
  peer endpoint = local relay transport virtual endpoint
```

如果用户态 WireGuard 引擎允许自定义 UDP transport，优先封装 transport trait：

```rust
pub trait PacketTransport {
    async fn send_to_peer(&self, peer: PeerId, packet: &[u8]) -> Result<()>;
    async fn recv_from_peer(&self, buf: &mut [u8]) -> Result<(PeerId, usize)>;
}
```

这样 direct UDP 和 Relay transport 可以共享 WireGuard 上层逻辑。

## 9. 端口映射协议

### Local Service Mapping

```proto
message PortMapping {
  string id = 1;
  string device_id = 2;
  string name = 3;
  string protocol = 4; // tcp, udp
  string local_host = 5;
  uint32 local_port = 6;
  uint32 virtual_port = 7;
  string access_scope = 8; // device, group, network
  bool enabled = 9;
}
```

访问方式：

```text
device-name.p2wlan:virtual_port
10.20.0.2:virtual_port
```

### Public Reverse Tunnel

公网映射必须走 Relay 或 Gateway：

```text
Internet client
  -> Relay public port
  -> encrypted reverse stream
  -> owner device local service
```

安全要求：

- 默认关闭。
- 必须显式 ACL。
- 支持访问日志。
- 支持带宽和连接数限制。

## 10. 错误码

| Code | 名称 | 含义 |
| --- | --- | --- |
| 1000 | AUTH_FAILED | 设备认证失败 |
| 1100 | DEVICE_NOT_AUTHORIZED | 设备未授权加入网络 |
| 1200 | PEER_NOT_FOUND | 目标节点不存在或不在线 |
| 2000 | STUN_FAILED | STUN 探测失败 |
| 2100 | SIGNAL_TIMEOUT | 信令超时 |
| 2200 | PUNCH_TIMEOUT | 打洞超时 |
| 2300 | DIRECT_PATH_FAILED | direct path 失效 |
| 2400 | RELAY_UNAVAILABLE | Relay 不可用 |
| 3000 | TUN_CREATE_FAILED | 虚拟网卡创建失败 |
| 3100 | ROUTE_APPLY_FAILED | 路由应用失败 |
| 4000 | ACL_DENIED | ACL 拒绝访问 |

## 11. Relay Protocol V1 协议与资源限制

### 11.1 资源限制配置
Relay 服务端和客户端均支持严格的资源边界参数配置：
- `outbound_queue_capacity` (服务端) / `cmd_queue_capacity` / `inbound_queue_capacity` (客户端): 限制队列深度，防止内存无上限增长。
- `register_timeout` (服务端 5s) / `idle_timeout` (服务端 30s): 连接建立后未按时注册或注册后长期无流量的连接将自动被断开。
- `max_connections` (服务端): 限制服务端最大并发 TCP 连接数。
- `max_frame_payload` (65535 字节): 单个帧的最大 Payload 长度。

### 11.2 二进制帧结构设计
所有帧均以 8 字节 header 开始，以避免在大帧分配内存前导致 OOM：
- `Magic` (4 字节): 统一为 `DERP` ('D', 'E', 'R', 'P')。
- `Version` (1 字节): 版本号，为 1。
- `Type` (1 字节): 帧类型 (Register=0x01, Registered=0x02, Forward=0x03, Received=0x04, Ping=0x05, Pong=0x06, Error=0x07, Close=0x08)。
- `Length` (2 字节): 网络字节序表示的 Payload 长度，若超出配置的最大值，服务器会直接拒绝且不为 Payload 分配内存。

### 11.3 协议错误码 (Wire Error Codes)

当 Relay 协议层发生错误时，将返回带有以下标准 2 字节代码的 `msgError` (0x07) 帧：

| 代码 (u16) | Snake Case 诊断码 | 触发场景与策略描述 |
| --- | --- | --- |
| `4000` | `invalid_frame` | 帧格式非法、未知帧类型或畸形 payload。 |
| `4001` | `unsupported_version` | 协议版本不匹配（当前版本为 1）。 |
| `4002` | `registration_required` | 建立连接后在发送注册帧前试图发送其他控制或数据帧。 |
| `4003` | `registration_timeout` | 建立连接后未在超时时间内完成注册，直接断开。 |
| `4004` | `duplicate_registration` | 同一 TCP 连接尝试对多个 Node ID 进行重复注册。 |
| `4005` | `connection_limit` | 服务端连接数达到上限，新连接将被立即拒绝。 |
| `4006` | `frame_too_large` | 帧的声明 Payload 长度超出 configured maximum frame payload。 |
| `4008` | `peer_backpressure` | 目标 peer 消费过慢，导致服务端 outbound 队列溢出，目标 peer 将被主动断开，并向发送端返回此错误。 |
| `4009` | `idle_timeout` | 客户端连接静默（无读写流量）时间超出最大闲置超时，连接被回收。 |
| `4010` | `transport_closed` | 传输层连接被远端关闭或丢失。 |
| `4011` | `auth_required` | 安全模式下，连接必须使用带 ticket 的 Auth Register 帧，不允许匿名注册。 |
| `4012` | `invalid_ticket` | ticket 格式无效、签名错误、算法不匹配或 kid 缺失。 |
| `4013` | `ticket_expired` | ticket 已过期（含时钟偏差 leeway 后仍超出 exp）。 |
| `4014` | `audience_mismatch` | ticket audience 与当前 Relay 实例不匹配。 |
| `4015` | `identity_mismatch` | ticket 中的 node_id/device_id 与 Auth Register frame 中声明的 node_id 不一致，或 sub 与 device_id 不匹配。 |
| `4016` | `network_mismatch` | ticket 中的 network_id 与当前 Relay 预期不符（跨网络转发被拒绝）。 |
| `4017` | `ticket_not_yet_valid` | ticket nbf 尚未到达（含时钟偏差 leeway）。 |
| `4018` | `unknown_ticket_key` | ticket 的 kid 不在当前 Relay 的公钥 keyring 中。 |

## 12. Phase A2 安全协议扩展

### 12.1 Relay Ticket JWT

控制面签发 EdDSA (Ed25519) JWT，Relay 验证后才接受注册。

**JWT Header:**
```json
{
  "alg": "EdDSA",
  "typ": "p2wlan-relay+jwt",
  "kid": "<key identifier>"
}
```

**JWT Claims (RelayTicketClaims):**
| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `iss` | string | 固定 `p2wlan-control` |
| `sub` | string | device ID（必须等于 `device_id`）|
| `aud` | string | Relay audience（与 Relay 实例配置精确匹配）|
| `iat` | int64 | 签发时间 (Unix seconds) |
| `nbf` | int64 | 不早于时间 |
| `exp` | int64 | 过期时间 |
| `jti` | string | 128-bit CSPRNG 随机值（hex 编码）|
| `device_id` | string | 设备 ID |
| `network_id` | string | 网络 ID（由控制面从数据库读取，不接受客户端填写）|
| `node_id` | string | 节点 ID（通常等于 device_id）|
| `relay_region` | string | 目标 Relay region |
| `relay_protocol` | int | 固定为 1 |

- 签名算法：`EdDSA`（严格锁定，不接受 `none`、`HS256` 或自动选择）。
- 默认 TTL：5 分钟，可配置 30 秒到 15 分钟。
- 允许的时钟偏差：默认 30 秒。
- ticket 绝不落盘、不进入日志、不进入 diagnostics。

### 12.2 Auth Register Frame (MSG_AUTH_REGISTER = 0x09)

替代旧 `MSG_REGISTER (0x01)` 的认证注册帧。

**Payload 布局 (strict binary):**
```text
u8   node_id_len         (1..255)
byte node_id[node_id_len] (valid UTF-8)
u16  ticket_len          (big-endian, 1..8192)
byte ticket[ticket_len]  (compact JWT)
```

约束：
- `node_id_len` 必须为 1..255。
- `node_id` 必须是合法 UTF-8。
- `ticket_len` 必须 > 0 且 ≤ 8192 (8 KiB)。
- 总 payload 仍受 A1 `max_frame_payload` 限制。
- payload 必须精确消费，禁止 trailing bytes。

### 12.3 注册状态机

```
安全模式（默认）:
  - MSG_AUTH_REGISTER (0x09): 验证 ticket → 成功则 Registered (0x02)
  - MSG_REGISTER (0x01): 返回 ERR_AUTH_REQUIRED (4011) 并关闭连接

开发模式 (allow_legacy_unauthenticated=true):
  - MSG_REGISTER (0x01): 匿名注册（仅开发/测试）
  - MSG_AUTH_REGISTER (0x09): 认证注册

客户端不允许在认证注册失败后自动回退匿名注册。
```

### 12.4 Network Binding

Relay peer table 以 `(network_id, node_id)` 为身份键：
- 不同 network 的相同 node_id 可以独立注册，互不替换。
- 转发（Forward）只在 source 的 network 内查找 target。
- 跨 network 目标对发送方表现为普通 `peer-not-found (404)`，不泄漏另一网络是否存在该 ID。
- 重复注册（同 network + 同 node_id）按 A1 规则处理：旧连接被关闭，旧连接退出不删除新连接。

### 12.5 TLS Transport

- 默认 TLS 1.3。
- 端点格式：`tls://host:port`（安全模式）；`tcp://host:port` 仅在 `allow_insecure_plaintext=true` 时可用。
- 客户端：使用系统可信根 + 可选 CA bundle；验证证书链、有效期和服务端名称。
- 服务端：加载证书链 + 私钥文件；缺少 TLS 配置且未显式开启明文模式时启动失败。
- 禁止：跳过证书验证、自动降级明文、dangerous accept-any-certificate。
- TLS handshake 受 register timeout 约束并计入连接限制。

### 12.6 密钥轮换

1. 将新 public key 部署到所有 Relay 的 keyring 中。
2. 切换 control 的 active signer 为新 kid。
3. 等待 `max_ticket_ttl + clock_skew`。此期间 current 和 previous key 均有效。
4. 从 keyring 删除旧 public key。旧 kid ticket 在此后被拒绝。

### 12.7 撤销边界

- 撤销 device credential 或删除 device 后，控制面停止签发新 ticket。
- 已签发的 ticket 最迟在短 TTL（默认 5 分钟）到期后失效。
- A2 不包含全局即时 jti 撤销列表。

### 12.8 Rust/Go 跨语言 Golden Vectors

Auth Register 测试向量（共享 fixtures）：

**Auth Register payload:**
```
node_id = "node-golden" (11 bytes)
ticket  = "test-jwt-token-value" (20 bytes)

Encoded bytes (hex):
0b 6e 6f 64 65 2d 67 6f 6c 64 65 6e 00 14 74 65 73 74 2d 6a 77 74 2d 74 6f 6b 65 6e 2d 76 61 6c 75 65
```

错误码对照表（Rust `RelayErrorCode` ↔ Go 常量）：
| Code | Rust | Go |
| --- | --- | --- |
| 4000 | `InvalidFrame` | `4000` |
| 4001 | `UnsupportedVersion` | `4001` |
| 4002 | `RegistrationRequired` | `4002` |
| 4003 | `RegistrationTimeout` | `4003` |
| 4004 | `DuplicateRegistration` | `4004` |
| 4005 | `ConnectionLimit` | `4005` |
| 4006 | `FrameTooLarge` | `4006` |
| 404 | `PeerNotFound` | `404` |
| 4008 | `PeerBackpressure` | `4008` |
| 4009 | `IdleTimeout` | `4009` |
| 4010 | `TransportClosed` | `4010` |
| 4011 | `AuthRequired` | `errAuthRequired` |
| 4012 | `InvalidTicket` | `errInvalidTicket` |
| 4013 | `TicketExpired` | `errTicketExpired` |
| 4014 | `AudienceMismatch` | `errAudienceMismatch` |
| 4015 | `IdentityMismatch` | `errIdentityMismatch` |
| 4016 | `NetworkMismatch` | `errNetworkMismatch` |
| 4017 | `TicketNotYetValid` | `errTicketNotYetVal` |
| 4018 | `UnknownTicketKey` | `errUnknownTicketKey` |

### 12.9 安全状态声明

A2 完成后：
- Relay 注册和传输已达到 Phase A2 安全基线。
- Probe v2 skeleton 已提供 MAC 验证、目标绑定和认证 peer-reflexive endpoint 学习；session-bound 临时密钥、nonce replay window、probe 限速预算和即时全局撤销仍属于 Phase A3。
- A2 不代表整个 P2WLAN 已完成安全审计或可用于公网生产运维。

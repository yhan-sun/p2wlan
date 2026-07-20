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

```text
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+---------------+---------------+-------------------------------+
| magic "P2WL"  | version       | msg_type                      |
+---------------+---------------+-------------------------------+
| session_id (128-bit)                                           |
+---------------------------------------------------------------+
| src_device_id_hash (128-bit)                                   |
+---------------------------------------------------------------+
| dst_device_id_hash (128-bit)                                   |
+---------------------------------------------------------------+
| timestamp_ms (64-bit)                                          |
+---------------------------------------------------------------+
| nonce_len      | nonce...                                      |
+---------------------------------------------------------------+
| signature_len  | signature...                                  |
+---------------------------------------------------------------+
```

消息类型：

| msg_type | 名称 | 方向 |
| --- | --- | --- |
| 1 | PROBE_SYN | A -> B |
| 2 | PROBE_ACK | B -> A |
| 3 | PROBE_KEEPALIVE | 双向 |
| 4 | PROBE_CLOSE | 双向 |

签名内容包括 session_id、src、dst、timestamp、nonce，防止伪造和重放。

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

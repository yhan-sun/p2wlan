# 架构

P2WLAN 将控制面、数据面和中继分开：

- Control Plane（Go + SQLite）负责账号、设备、虚拟地址、房间、信令、凭据、Relay catalog，以及持久化 daemon 上报的权威活动路径观测与有界迁移历史，提供只读 Admin Connections API。
- Rust daemon 负责 TUN、路由、Peer、NAT traversal、加密会话、路径状态、Direct/Relay 选择与向 Control 异步上报权威路径遥测。daemon 是活动路径事实的唯一所有者，Control 不推断或猜测数据面路径。
- Relay（Go）验证短期票据并转发密文，不解密业务载荷。
- Flutter 提供跨平台客户端界面；CLI 复用 daemon 的本地控制接口。

Control 的 HTTPS/WSS 只负责控制、信令和路径遥测上报，Relay 的 TLS 连接负责数据转发。服务器不会因为部署了 Control/Relay 就自动加入房间或替客户端创建 TUN。

## 界面边界

Flutter 是终端用户的客户端界面，管理本机账号、设备、房间、诊断和 daemon 生命周期；客户端功能仍以 Flutter 与本地 daemon 契约为准。`server/admin-ui/` 是部署者使用的服务器运维控制台，只读取 Control 能确认的服务端状态与只读连接遥测，并与 `p2wlan-control` 同 origin、同二进制发布。

两类界面不是同一产品表面：服务器管理台不会替代 Flutter，不直接控制客户端 TUN，也不拥有 daemon 的 Direct/Relay 路径状态。Control 仅持久化 daemon 通过 `path_telemetry_v1` 权威上报的有界状态快照与迁移记录，并不推算或干预路径。管理台把这些事实分成两类产品视图：Relationships 展示 Control 资源归属，Connections 展示 daemon 权威单向路径观测；Live Topology 只是选定网络下 fresh Connections 的可视化，不是新的路径状态所有者。Connection Health 同样只是对当前 snapshot 与受限 transition history 的请求时聚合，不持久化独立健康状态，也不会把 Relay 或 RTT 自行推断成路径故障；管理台的 Health 工作区只是该只读聚合的呈现层，并复用 Connections 的 directional detail/timeline，而不是维护另一套连接状态。客户端界面收敛到 Flutter 的规则不禁止 Control 提供独立的运维管理面；反过来，服务器管理台新增能力也不能绕过 Flutter/daemon 的客户端契约。

当前数据面是自包含的 WireGuard-like Noise 实现，不是官方 WireGuard，也不声明 WireGuard 互操作兼容。实现细节以源码、协议测试和发布身份检查为准。

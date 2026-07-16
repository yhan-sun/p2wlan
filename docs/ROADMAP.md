# P2WLAN 开发路线图

Version: 0.1  
Date: 2026-07-16

## 路线原则

- 先打通数据面，再完善控制面。
- 先 Linux MVP，再做 Windows/macOS。
- 先 direct UDP，再 Relay fallback。
- 先 CLI 和诊断命令，再做桌面 UI。
- 每个阶段都必须可编译、可运行、可测试。

## Phase 0: 工程初始化

目标：建立可长期维护的 monorepo。

交付物：

- Rust workspace。
- Go module。
- protobuf 目录和生成脚本。
- 基础 CI：fmt、clippy、go test、protobuf lint。
- 开发文档和本地运行脚本。

验收标准：

- `cargo test --workspace` 通过。
- `go test ./...` 通过。
- `make proto` 或等价命令可以生成 Rust/Go 代码。

## Phase 1: Linux 虚拟网卡 MVP

目标：客户端能创建 TUN 设备并读写 IP packet。

交付物：

- `p2wlan-tun` crate。
- Linux TUN 实现。
- 虚拟 IP 和 MTU 配置。
- 路由配置和清理逻辑。
- CLI：`p2wlan tun up/down/status`。

验收标准：

- Linux 上创建 `p2wlan0`。
- 能配置 `10.20.0.2/24`。
- 能从 TUN 读到 ICMP packet。
- 退出后路由和设备清理正确。

## Phase 2: 本地 WireGuard 数据面

目标：两台 Linux 节点在已知 endpoint 下建立加密虚拟内网。

交付物：

- WireGuard 用户态引擎封装。
- peer config 下发的本地配置文件格式。
- UDP transport。
- packet pump：TUN <-> WireGuard <-> UDP。
- CLI：`p2wlan peer add`、`p2wlan status`。

验收标准：

- 两台机器手动配置 endpoint 后可以互 ping。
- TCP 服务可通过虚拟 IP 访问。
- 重启 daemon 后连接可恢复。
- 空闲 CPU 低于 1%，内存低于 50 MB。

## Phase 3: 控制面 MVP

目标：不用手写 peer 配置，控制面分配虚拟 IP 并下发 network map。

交付物：

- Go control server。
- 设备注册 API。
- 网络和 IP 分配。
- network map 拉取和 watch。
- SQLite 或 PostgreSQL 存储。
- 开发用 token auth。

验收标准：

- 新设备注册后获得虚拟 IP。
- 两设备能看到彼此 peer config。
- 修改设备名称或下线状态后客户端能收到更新。

## Phase 4: STUN 与 UDP Hole Punching

目标：节点通过公网候选地址自动直连。

交付物：

- STUN client。
- STUN server 或兼容第三方 STUN server。
- candidate gather。
- Signaling service。
- probe packet 和打洞状态机。
- 连接诊断输出。

验收标准：

- 两个不同 NAT 后的节点可以自动直连。
- 可以显示 local endpoint、public endpoint、selected endpoint。
- 直连失败原因可诊断。
- direct path 断开后能触发重探测。

## Phase 5: Relay Fallback

目标：对称 NAT、UDP 受限或企业网络下仍能连通。

交付物：

- Relay server。
- Relay session 注册和身份认证。
- Relay frame 转发。
- direct/relay 自动切换。
- Relay region 选择。

验收标准：

- 禁止 direct UDP 后，节点仍能通过 Relay ping 通。
- Relay 不解密用户流量。
- direct 恢复后可以切回 direct。
- 客户端状态能清晰显示 `relay`。

## Phase 6: 端口映射与 DNS

目标：支持更自然的服务访问方式。

交付物：

- Magic DNS。
- Local service mapping。
- TCP proxy。
- UDP proxy。
- 端口映射 ACL。
- CLI：`p2wlan port add/list/remove`。

验收标准：

- `device-name.p2wlan` 能解析到虚拟 IP。
- 节点本地 `127.0.0.1:8080` 可暴露给虚拟网络内访问。
- ACL 拒绝时连接失败且日志可解释。

## Phase 7: 桌面端与跨平台

目标：完善用户体验，补齐 Windows/macOS。

交付物：

- Tauri + React 桌面 UI。
- Windows Wintun 实现。
- macOS utun 或 Network Extension 实现。
- 原生安装包。
- 日志导出和诊断包。

验收标准：

- Windows/macOS/Linux 均可加入同一网络。
- UI 能展示设备、连接类型、延迟、端口映射。
- 安装、升级、卸载流程不会遗留虚拟网卡和路由。

## 测试矩阵

| 测试类型 | 场景 |
| --- | --- |
| 单元测试 | TUN 配置解析、candidate 排序、ACL 匹配、protobuf 编解码 |
| 集成测试 | 两节点同机 namespace、两 VM 直连、Relay fallback |
| NAT 实验 | Full cone、restricted、port restricted、symmetric、CGNAT |
| 平台测试 | Linux x86_64/aarch64、Windows 11、macOS Apple Silicon |
| 性能测试 | ping RTT、iperf3 吞吐、Relay 带宽、100 peers network map |
| 安全测试 | 未授权设备、伪造信令、重放 probe、ACL 拒绝 |

## 性能基准计划

第一版 benchmark：

```text
direct ping overhead
direct iperf3 throughput
relay ping overhead
relay iperf3 throughput
idle memory
idle CPU
reconnect time
direct-to-relay failover time
relay-to-direct recovery time
```

记录格式：

```text
date:
git commit:
os:
cpu:
network:
client version:
server version:
result:
notes:
```

## 风险控制

- 如果 WireGuard 用户态集成阻塞，先实现 mock-free 的 UDP encrypted transport proof，但必须标记为临时方案，并尽快替换。
- 如果 macOS Network Extension 权限阻塞，开发阶段先支持 utun，正式分发再切 NEPacketTunnelProvider。
- 如果 Windows Wintun 分发阻塞，先文档化安装驱动要求，避免把客户端逻辑和驱动安装耦合。
- 如果 NAT 直连率低，先优化诊断和 Relay 可用性，再研究更复杂的端口预测和 peer relay。


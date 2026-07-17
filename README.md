# P2WLAN

P2WLAN 是一个面向私有化部署的 P2P 虚拟内网系统设计稿。目标是实现高性能、跨平台、低内存、尽量原生调用系统网络 API 的虚拟局域网能力，支持节点间 P2P 通信、NAT 穿透、中继 fallback、端口映射和内网互访。

当前仓库已经合入第一版半成品实现：Rust 客户端核心、Go 控制面服务、React 桌面 UI 原型和 protobuf 草案均已入库。代码可以编译和测试，但还不是可直接生产使用的完整虚拟内网产品。

## 文档入口

- [P2PNet-Design.md](./P2PNet-Design.md): 项目总体设计文档，包含产品目标、架构、技术选型和验收标准。
- [docs/PROTOCOL.md](./docs/PROTOCOL.md): 协议与状态机草案，包含身份、信令、NAT 穿透、Relay 和端口映射协议。
- [docs/ROADMAP.md](./docs/ROADMAP.md): 分阶段开发路线图、验收标准、测试矩阵和风险控制。
- [docs/RESEARCH_NOTES.md](./docs/RESEARCH_NOTES.md): 参考项目与技术调研笔记。
- [docs/AI_IMPLEMENTATION_PROMPT.md](./docs/AI_IMPLEMENTATION_PROMPT.md): 可直接交给 Coding Agent 的实现提示词。

## 当前代码结构

- `client/`: Rust workspace，包含 TUN、crypto、WireGuard、NAT、Relay 和 daemon 模块。
- `server/`: Go 控制面服务，包含认证、设备/数据库 API 和 signaling WebSocket。
- `src/`: React + Vite 桌面 UI 原型。
- `proto/`: 网络协议 protobuf 草案。

## 当前实现状态

- 已打通：daemon 注册控制面、分配虚拟 IP、轮询 peer map、TUN 出站包按虚拟 IP 路由到 peer。
- 已打通：出站包通过已建立的 WireGuard transport session 加密，并经 direct UDP socket 发送到 peer endpoint。
- 已打通：direct UDP 入站 datagram 可进入 WireGuard transport 解密，并将解密后的 IP 包写回 TUN。
- 已打通：控制面可通过 REST signaling 队列交换 WireGuard handshake offer/answer，并由 daemon 自动安装 transport session。
- 已打通：daemon 可通过 `network.udp_bind` / `--udp-bind` 绑定 UDP，本地或公网可见地址可通过 `network.udp_advertise` / `--udp-advertise` 上报控制面。
- 已打通：daemon 可收集 host/STUN UDP candidates，并通过 signaling offer/answer 交换；peer 端会从 candidates 中选择可解析 endpoint。
- 已打通：daemon 收到 peer candidates 后会主动发送 UDP punch probes，入站 PNCH 包会自动 ACK 且不会进入 WireGuard 数据面，direct endpoint 会定期发送 keepalive 刷新 NAT 映射。
- 已打通：daemon 可连接配置的 relay server（`relay.servers` / `--relay`），当 direct UDP 未验证、无 endpoint 或发送失败时可把加密 WireGuard datagram 通过 relay fallback 转发，relay 入站流量会回灌 WireGuard 解密。
- 已打通：Relay region 自动选择支持 `region@endpoint` 候选、区域偏好、并发连接耗时比较和不可达候选回退；relay 使用控制面分配的 node ID 注册，选择报告可从 diagnostics 查看。
- 已打通：peer path health 会记录 direct/relay 成功和失败；direct 通过 UDP punch ACK 或入站数据确认，失败后自动切到 relay，并在后台继续 probe direct 以便恢复。
- 已打通：daemon 可通过 `--diagnostics-bind 127.0.0.1:39277` 暴露本地 `/status` JSON，并可用 `p2pnet-daemon --status --diagnostics-url http://127.0.0.1:39277/status` 查看 peer path health、bytes、endpoint、relay 状态和失败原因。
- 已提供：Linux root/network namespace 真实双节点 TUN ping smoke，覆盖双向 ICMP、WireGuard/direct UDP 数据面和 diagnostics 路径状态。
- 仍待补齐：在 Linux CI/测试机持续执行真实 TUN smoke、Relay 跨区域互联与动态重选。

## 本地验证

```bash
cargo test --workspace --all-targets

cd server
go test ./...

cd ..
pnpm install
pnpm run build

# Control-plane smoke test: starts server + two daemon instances without TUN/root
# and verifies registration, WireGuard sessions, UDP candidates, punch probes, and diagnostics
./scripts/control-smoke.sh

# Real data-plane smoke test: requires Linux root, iproute2,
# ping, curl, and a prebuilt daemon binary. It skips elsewhere by default.
cargo build -p p2pnet-daemon
sudo -E ./scripts/tun-ping-smoke.sh
```

设置 `P2WLAN_REQUIRE_TUN_SMOKE=1` 可将平台、权限或依赖缺失从 skip 改为失败，适合 Linux CI 强制执行。

本地运行 daemon 时可打开诊断端口：

```bash
p2pnet-daemon --config p2pnet-config.json --diagnostics-bind 127.0.0.1:39277
p2pnet-daemon --status --diagnostics-url http://127.0.0.1:39277/status
```

Relay 候选可使用 `region@endpoint` 标注区域，未标注的旧格式仍归入 `default` 区域：

```bash
p2pnet-daemon \
  --relay cn-shanghai@198.51.100.10:8080,cn-hongkong@203.0.113.20:8080 \
  --relay-regions cn-shanghai,cn-hongkong \
  --relay-selection-timeout-ms 3000
```

选择顺序为区域偏好、连接与注册耗时、配置顺序。当前 relay server 尚无跨区域互联，同一虚拟网络应使用一致的候选列表；endpoint 当前必须是可解析的 `IP:port` 或 `[IPv6]:port`。

如果本机 Go 出现标准库版本不一致，优先使用 Homebrew 的 GOROOT：

```bash
GOROOT=/opt/homebrew/opt/go/libexec /opt/homebrew/opt/go/libexec/bin/go test ./...

GOROOT=/opt/homebrew/opt/go/libexec GO_BIN=/opt/homebrew/opt/go/libexec/bin/go ./scripts/control-smoke.sh
```

## 推荐实现路线

1. 先做 Rust 客户端核心：虚拟网卡抽象、Linux TUN、包读写测试。
2. 再接入用户态 WireGuard 引擎，完成同局域网内两节点虚拟 IP 通信。
3. 完善 UDP hole punching 探测、keepalive 和重连状态机，实现真正跨 NAT P2P。
4. 增加 Relay fallback，覆盖对称 NAT、企业网络和 UDP 受限环境。
5. 最后补齐 UI、DNS、ACL、子网路由和端口映射。

## 项目定位

P2WLAN 的目标不是一开始复制完整商业级 Tailscale/ZeroTier，而是先做一个可运行、可验证、可逐步扩展的虚拟内网内核：

- 数据面优先，确保两台机器能通过虚拟 IP 通信。
- P2P 优先，Relay 只作为失败兜底。
- 控制面集中管理，数据面端到端加密。
- 先支持 Linux/macOS/Windows 桌面端，再扩展移动端。

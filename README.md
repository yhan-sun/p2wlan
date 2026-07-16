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
- 仍待补齐：STUN/打洞 endpoint 选择、真实双节点 TUN ping 验证、Relay fallback 数据面。

## 本地验证

```bash
cargo test --workspace --all-targets

cd server
go test ./...

cd ..
pnpm install
pnpm run build

# Control-plane smoke test: starts server + two daemon instances without TUN/root
./scripts/control-smoke.sh
```

如果本机 Go 出现标准库版本不一致，优先使用 Homebrew 的 GOROOT：

```bash
GOROOT=/opt/homebrew/opt/go/libexec /opt/homebrew/opt/go/libexec/bin/go test ./...

GOROOT=/opt/homebrew/opt/go/libexec GO_BIN=/opt/homebrew/opt/go/libexec/bin/go ./scripts/control-smoke.sh
```

## 推荐实现路线

1. 先做 Rust 客户端核心：虚拟网卡抽象、Linux TUN、包读写测试。
2. 再接入用户态 WireGuard 引擎，完成同局域网内两节点虚拟 IP 通信。
3. 加入 STUN、信令服务和 UDP hole punching，实现真正 P2P。
4. 增加 Relay fallback，覆盖对称 NAT、企业网络和 UDP 受限环境。
5. 最后补齐 UI、DNS、ACL、子网路由和端口映射。

## 项目定位

P2WLAN 的目标不是一开始复制完整商业级 Tailscale/ZeroTier，而是先做一个可运行、可验证、可逐步扩展的虚拟内网内核：

- 数据面优先，确保两台机器能通过虚拟 IP 通信。
- P2P 优先，Relay 只作为失败兜底。
- 控制面集中管理，数据面端到端加密。
- 先支持 Linux/macOS/Windows 桌面端，再扩展移动端。

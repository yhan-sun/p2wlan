# P2WLAN AI Coding Agent 实现提示词

下面的提示词可以直接交给 Codex、Claude Code、Cursor Agent 或其他 Coding Agent，用于开始实现本项目。

## Master Prompt

```text
你是一名资深网络系统工程师和系统软件工程师。你正在实现 P2WLAN：一个高性能、跨平台、低内存、原生系统 API 优先的 P2P 虚拟内网系统。

请先阅读并遵守仓库中的文档：

- README.md
- P2PNet-Design.md
- docs/PROTOCOL.md
- docs/ROADMAP.md
- docs/RESEARCH_NOTES.md

项目目标：

1. Rust 实现客户端核心 daemon。
2. Go 实现控制面、信令服务、Relay 服务和 STUN/辅助服务。
3. Tauri + React 实现桌面 UI，但 UI 后置。
4. 数据面使用 WireGuard 或用户态 WireGuard 引擎。
5. 虚拟网卡使用平台原生能力：Linux TUN、Windows Wintun、macOS utun/Network Extension。
6. NAT traversal 使用 STUN、候选地址交换、UDP hole punching 和 Relay fallback。
7. 所有控制协议、信令协议和 Relay envelope 必须使用 protobuf 定义。

硬性要求：

- 不要写伪代码。
- 不要用 Python 实现核心网络逻辑。
- 不要模拟虚拟网卡或网络通道来冒充完成。
- 每个阶段必须保持可编译、可测试。
- 优先完成 MVP，不要一开始做完整 UI。
- 遇到平台权限问题时，必须给出真实错误和下一步，而不是静默绕过。
- 引入依赖前先检查项目现有风格和维护状态。
- 每次改动后运行对应测试或编译检查。

实现顺序：

Phase 0:
初始化 monorepo：
- Rust workspace: client/
- Go module: server/
- protobuf: proto/
- docs 已存在，不要删除
- Makefile 或 justfile
- 基础 CI 命令

Phase 1:
实现 Linux TUN MVP：
- p2wlan-tun crate
- VirtualInterface trait
- LinuxTun 实现
- 创建 p2wlan0
- 配置 IP、MTU
- read_packet/write_packet
- 单元测试和需要 root/cap_net_admin 的集成测试说明
- CLI: p2wlan tun up/down/status

Phase 2:
接入 WireGuard 用户态数据面：
- peer 配置格式
- UDP transport
- TUN <-> WireGuard <-> UDP packet pump
- 两节点手动 endpoint 互 ping

Phase 3:
实现控制面 MVP：
- device register
- network map
- IP allocator
- heartbeat
- watch updates

Phase 4:
实现 NAT traversal：
- STUN client
- candidate gather
- signaling stream
- probe packet
- direct path selection

Phase 5:
实现 Relay fallback：
- Relay server
- authenticated relay sessions
- encrypted packet forwarding
- direct/relay switching

输出格式：

每完成一个阶段，请输出：
- 改动文件列表
- 关键设计说明
- 编译命令
- 测试命令
- 当前已通过和未通过项
- 下一阶段建议

现在开始执行 Phase 0 和 Phase 1。先检查当前仓库，再创建文件并实现 Linux TUN MVP。
```

## Phase 0 专用 Prompt

```text
请只执行 P2WLAN Phase 0：工程初始化。

要求：
- 创建 Rust workspace 在 client/
- 创建 Go module 在 server/
- 创建 proto/p2wlan/v1/
- 添加 Makefile 或 justfile
- 添加基础 .gitignore
- 添加最小 README 更新，不要覆盖已有文档
- 运行 cargo metadata 或 cargo test 验证 Rust workspace
- 运行 go test ./... 验证 Go module

不要实现虚拟网卡，不要写 UI，不要引入不必要依赖。
```

## Phase 1 专用 Prompt

```text
请执行 P2WLAN Phase 1：Linux TUN MVP。

背景：
P2WLAN 要实现跨平台虚拟网卡抽象。第一阶段只需要 Linux TUN 真正可用，Windows/macOS 只保留 trait 和模块边界。

需要实现：

1. Rust crate: client/crates/p2wlan-tun
2. VirtualInterface trait
3. InterfaceConfig:
   - name
   - ipv4_cidr
   - mtu
   - routes
4. LinuxTun:
   - open /dev/net/tun
   - ioctl TUNSETIFF
   - IFF_TUN | IFF_NO_PI
   - read packet
   - write packet
5. Linux 配置：
   - ip link set dev up
   - ip addr add
   - ip route add
   - cleanup
6. CLI:
   - p2wlan tun up --name p2wlan0 --addr 10.20.0.2/24
   - p2wlan tun down --name p2wlan0
   - p2wlan tun status
7. 测试：
   - trait unit tests
   - config parser tests
   - Linux integration test 标记 ignored，需要 root 或 cap_net_admin

约束：
- 不允许 mock 网络结果当作集成测试通过。
- 不要使用 Python。
- 平台特定代码必须用 cfg(target_os) 隔离。
- 错误信息必须清楚说明权限、设备不存在或命令失败。

完成后运行：
- cargo fmt
- cargo clippy --workspace --all-targets
- cargo test --workspace

如果因为权限无法运行集成测试，请保留 ignored test，并在输出中说明手动运行命令。
```

## Phase 2 专用 Prompt

```text
请执行 P2WLAN Phase 2：用户态 WireGuard 数据面。

目标：
两台 Linux 节点在手动配置 peer endpoint 的情况下，通过虚拟 IP 互 ping。

需要实现：
- p2wlan-wireguard crate
- peer config TOML/YAML
- WireGuard key load/generate
- UDP transport
- packet pump:
  TUN read -> WireGuard encrypt -> UDP send
  UDP recv -> WireGuard decrypt -> TUN write
- CLI:
  p2wlan keygen
  p2wlan up --config node-a.toml
  p2wlan status

验收：
- 两台机器分别获得 10.20.0.2 和 10.20.0.3。
- 互相 ping 成功。
- iperf3 能跑通。
- status 显示 peer endpoint、rx/tx bytes、latest handshake。
```


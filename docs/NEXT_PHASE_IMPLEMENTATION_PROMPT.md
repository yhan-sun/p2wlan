# P2WLAN 下一阶段 Coding Agent 实现提示词

下面的 `Master Prompt` 可以直接交给 Codex、Claude Code、Cursor Agent 或其他具备终端和代码编辑能力的 Coding Agent。

这不是一份头脑风暴题，而是一份实现与验收合同。不要只输出方案；必须阅读现有代码、完成实现、运行测试、保留证据，并明确报告仍未通过的项目。

## Master Prompt

```text
你是一名资深网络系统工程师、安全工程师和 Rust/Go 工程师。你将在现有仓库中继续实现 P2WLAN，而不是从零重写。

仓库：yhan-sun/p2wlan
当前主分支基线提交应不早于：7eb35f0 test: harden linux tun smoke

一、开始前必须完成的工作

1. 阅读以下文件：
   - README.md
   - P2PNet-Design.md
   - docs/PROTOCOL.md
   - docs/ROADMAP.md
   - docs/RESEARCH_NOTES.md
   - docs/AI_IMPLEMENTATION_PROMPT.md
   - docs/NEXT_PHASE_IMPLEMENTATION_PROMPT.md
   - scripts/control-smoke.sh
   - scripts/tun-ping-smoke.sh

2. 阅读并理解现有关键实现：
   - client/daemon/src/main.rs
   - client/daemon/src/lib.rs
   - client/daemon/src/control.rs
   - client/daemon/src/dataplane.rs
   - client/daemon/src/transport.rs
   - client/daemon/src/udp.rs
   - client/daemon/src/relay.rs
   - client/daemon/src/peer.rs
   - client/tun/src/platform/linux.rs
   - client/wireguard/src/handshake.rs
   - client/wireguard/src/session.rs
   - client/relay/src/server.rs
   - server/main.go
   - server/api/api.go
   - server/auth/auth.go
   - server/database/database.go
   - server/signaling/signaling.go

3. 在修改前运行并记录基线：
   - git status --short --branch
   - cargo fmt --all --check
   - cargo test --workspace --all-targets
   - cargo clippy --workspace --all-targets --all-features -- -D warnings
   - cd server && go test ./... -count=1 && go vet ./...
   - pnpm run build
   - pnpm audit --audit-level high
   - ./scripts/control-smoke.sh

4. 不得覆盖或回滚用户已有修改。工作区不干净时，先辨认改动来源，保留无关改动。

二、项目当前真实状态

已经完成并验证：

- Rust daemon、Go 控制面、Linux TUN、UDP 数据面和本地诊断接口可以编译运行。
- 两个 Linux network namespace 已经通过真实 TUN、加密 transport 和 direct UDP 双向 ping。
- 控制面可注册设备、分配虚拟 IP、轮询 peer map、交换候选地址和握手消息。
- direct UDP、punch probe、keepalive、Relay fallback、静态 Relay region 选择已有实现。
- Rust workspace 当前约有 278 个测试。

尚未完成，且本次必须优先处理：

- daemon 在控制面注册前创建 TUN，服务端分配的虚拟 IP 没有真正用于配置网卡。
- overlay 系统路由由 smoke 脚本手工添加，daemon 没有路由安装和清理生命周期。
- 控制面 API 只验证“用户已登录”，没有验证 network/device/tunnel/signal 的资源归属。
- 相同公开密钥重新注册时可能把已有设备转移给另一个用户。
- 信令 API 允许客户端自行填写 from_node_id，也允许任意已登录用户读取其他节点信令。
- Relay 使用明文 TCP、匿名 node ID 注册和无界发送队列。
- 控制面或 Relay 断线后没有完整自动恢复。
- session rekey 条件存在，但没有被运行时调用。
- ACL、DNS、端口映射目前主要是状态模型，不是已接入的数据面功能。
- UI 是演示原型，不是当前阶段重点。
- Go 服务端目前没有测试；仓库没有 CI、发布、systemd 和正式 Relay 可执行程序。
- 严格 Clippy 当前失败；前端依赖审计存在高危和中危告警。

三、本次总目标

把项目从“Linux 数据面技术原型”推进为“可在受控环境部署和长期运行的 Linux 私测版”。

最终用户流程必须是：

1. 部署 control 和 relay。
2. 用户创建网络并授权两台 Linux 设备。
3. 两台设备只提供控制面地址和合法凭据即可启动。
4. daemon 从控制面获得虚拟 IP/CIDR/Relay/STUN 配置。
5. daemon 自动创建 TUN、配置 IP、安装 overlay 路由。
6. 两台设备通过虚拟 IP 互 ping、访问 TCP 服务。
7. direct UDP 不可用时自动走 Relay，direct 恢复后自动切回。
8. control 或 relay 短暂重启后，客户端无需人工重启即可恢复。
9. 未授权用户无法查看、修改、冒充或消费其他网络和设备的数据。
10. daemon 退出或卸载后不遗留错误路由和虚拟网卡。

四、不可违反的工程约束

- 不要重写整个仓库；优先复用现有模块和测试。
- 不要用 mock、日志文本或手工添加路由冒充产品流程完成。
- 不要在 smoke 脚本中预先指定服务端本应分配的虚拟 IP。
- 不要在 smoke 脚本外部执行 ip route 来掩盖 daemon 缺少路由管理。
- 不要仅隐藏 Clippy、安全审计或测试错误；修复原因，必要的 allow 必须附带理由。
- 不要自创新的加密算法、签名算法或 token 格式。
- 不要把 X25519 当作签名算法使用。需要设备签名时使用成熟的 Ed25519 库。
- 不要把当前自研 WireGuard-like 实现描述为已审计或已与标准 WireGuard 互操作。
- 不要把 JWT、设备 token、私钥、SSH 私钥或测试服务器凭据提交到仓库或打印到日志。
- 不要在低内存远端服务器上编译 Rust。应在本地或 CI 交叉编译，远端只上传二进制并运行测试。
- 远端测试必须使用临时目录、唯一端口和严格 cleanup，测试结束后检查无残留进程、netns、网卡、路由和防火墙规则。
- 每个阶段独立提交。提交信息要描述行为，不要使用“update”“fix stuff”等模糊文字。
- 未获得明确授权时不要强推、改写历史或删除用户分支。
- 缺少真实主机或权限时，必须把对应验收项标记为 PENDING，不能宣称完成。

五、实施阶段

Stage 0：建立可靠基线

目标：让代码质量检查成为后续工作的硬门槛。

必须实现：

1. 使用成熟 CLI parser（优先 clap）替代手工 Vec<String> 参数解析。
2. `p2pnet-daemon --help` 和 `--version` 必须零副作用：
   - 不生成配置文件。
   - 不连接控制面。
   - 不创建 TUN。
3. 未知参数、缺失参数值、非法端口、非法 IP、非法 MTU 必须返回非零退出码和清楚错误。
4. 修复严格 Clippy 错误，使以下命令通过：
   cargo clippy --workspace --all-targets --all-features -- -D warnings
5. 升级前端依赖，消除 `pnpm audit --audit-level high` 的高危项；不要进行无关 UI 重构。
6. 添加 CI：
   - Rust fmt、Clippy、tests。
   - Go test、go vet。
   - 前端 build 和 high-level audit。
   - Linux target 编译。
7. 更新 README 中准确的构建和测试命令。

Stage 0 验收：

- 在一个全新临时目录中执行 daemon --help，目录保持为空。
- 所有基线命令通过。
- CI 配置不依赖仓库外的本机绝对路径。

Stage 1：控制面分配 IP 与真实路由生命周期

目标：取消手工虚拟 IP 和手工路由，让控制面配置真正成为运行时事实来源。

必须实现：

1. 调整 daemon 启动状态机：
   - 加载本地身份和控制面配置。
   - 注册控制面并等待初始 network map。
   - 验证服务端返回的 virtual IP、CIDR、node ID。
   - 使用服务端结果创建并配置 TUN。
   - 安装 overlay 路由。
   - 然后启动数据面和 peer handshake。
2. 区分两种明确模式：
   - managed：IP/CIDR 由控制面分配，默认模式。
   - manual/offline：仅用于诊断和明确的手工部署，必须显式开启。
   不允许 managed 模式悄悄使用默认的 10.20.0.1。
3. 新增平台路由抽象，Linux 实现必须真实可用：
   - 添加 overlay CIDR 或精确 peer 路由。
   - 幂等处理已经存在的正确路由。
   - 检测冲突路由，禁止静默覆盖不属于 P2WLAN 的路由。
   - daemon 正常退出时清理自己创建的路由。
   - 异常退出后再次启动能够恢复和修正自身状态。
4. 优先使用原生 API/netlink；如果暂时调用系统命令，必须使用参数化 Command，不得拼接 shell 字符串，并完整检查退出状态。
5. 不要为了 Linux 功能破坏 macOS/Windows 编译边界。其他平台可以明确返回 Unsupported，但不能伪装成功。
6. 修复控制面 IP 分配：
   - 不得使用 COUNT(*) + 2。
   - 使用事务分配空闲地址并处理并发注册。
   - 增加 network_id + virtual_ip 唯一约束。
   - 增加 network_id + public_key 唯一约束。
   - 正确处理删除设备后地址复用和网段耗尽。
   - 启用 SQLite foreign_keys。
   - 创建真实 default network 迁移或提供明确网络创建 API，不能依赖关闭外键才能运行。
7. 修改 scripts/tun-ping-smoke.sh：
   - 不向 daemon 传 `--address`。
   - 不用 `ip route replace` 添加 overlay peer 路由。
   - 从 diagnostics 或控制面响应验证实际分配 IP。
   - 继续验证双向 ICMP 和 active_path=direct。

Stage 1 验收：

- 全新数据库启动两个节点，自动得到不冲突的地址。
- Linux namespace smoke 不含外部 overlay 路由补丁仍然通过。
- daemon 退出后自己创建的路由被清理。
- 两个并发注册请求不会得到相同地址。
- 网段耗尽返回可诊断错误，不生成非法 IPv4 地址。

Stage 2：控制面授权与设备身份

目标：任何 API 操作都绑定到经过认证的用户、网络和设备，不能靠客户端提交 ID 决定身份。

必须实现：

1. 建立并迁移清晰的数据模型：
   - users
   - networks
   - network_memberships 或等价关系
   - devices
   - signals
   - tunnels
   - device credentials/challenges
2. 用户只能访问自己拥有或加入的网络。
3. 设备必须属于当前用户可访问的网络。
4. 已存在设备的公开密钥不能被另一用户重新注册或转移。
5. 设备注册加入密钥持有证明：
   - 使用维护良好的 Ed25519 实现。
   - 服务端发放随机、短期、单次 challenge。
   - 客户端对定义清楚的 canonical message 签名。
   - 服务端验证签名、过期时间、单次消费和重放。
   - X25519 tunnel key 与 Ed25519 device identity 分开保存和说明。
6. 注册完成后签发可撤销、可过期、绑定 device_id/network_id 的设备凭据。
   - 数据库只保存 opaque token 的安全 hash，或使用经过验证且用途受限的标准 token。
   - daemon 后续轮询、端点更新和信令使用设备身份，不长期复用用户 JWT。
7. 修改所有敏感 API：
   - ListNodes 只能列出已授权网络。
   - Update/DeleteDevice 必须验证设备归属。
   - CreateSignal 的 from_node_id 必须由认证上下文产生，忽略或拒绝客户端伪造值。
   - ListSignals 只能消费当前认证设备的信令。
   - to_node_id 必须与发送方处于同一网络。
   - Tunnel create/list/delete 必须验证设备和隧道归属。
8. 增加输入保护：
   - HTTP body 大小上限。
   - email/password/名称/端口/candidate 数量和长度验证。
   - ReadHeaderTimeout。
   - 登录和注册基础限流。
   - 服务启动时发现默认 JWT secret 必须拒绝启动，测试环境需显式配置。
9. 配置文件中的私钥和设备 token 必须以 0600 权限原子写入；日志不得输出它们。

Stage 2 必须新增 Go 测试：

- 用户 A 不能列出用户 B 的私有网络。
- 用户 A 不能更新或删除用户 B 的设备。
- 用户 A 不能用用户 B 的公开密钥接管设备。
- 设备 A 不能伪造设备 B 发送信令。
- 设备 A 不能消费设备 B 的信令。
- 不同网络节点不能互发信令。
- challenge 过期、重复使用、错误签名都失败。
- 并发 IP 分配无冲突；外键约束真实生效。

Stage 3：控制连接、握手和路径恢复

目标：短暂网络故障和服务重启不能要求用户人工重启 daemon。

必须实现：

1. 控制面注册、轮询和信令失败使用带 jitter 的指数退避。
2. 区分 4xx 永久认证失败与 5xx/超时等可重试失败。
3. token 失效时给出明确 diagnostics，不允许无休止快速重试。
4. 重连后重新注册/恢复设备会话、刷新 network map、清理离线 peer、重新握手。
5. pending handshakes 有超时、去重、失败清理和重试上限。
6. 将 session rekey 真正接入运行时：
   - 时间阈值。
   - 消息计数阈值。
   - 重连和密钥轮换期间不接受旧 session 无限存活。
7. Relay 连接断开后自动重连并重新选择候选。
8. 当前 Relay 不可达时 diagnostics 必须显示每个候选的最近失败和下次重试时间。
9. direct path 失败切 Relay、Relay 期间重探 direct、direct 恢复切回的状态机必须有集成测试。
10. 使用 task supervision：关键数据面任务异常退出时，daemon 不能只打印 warning 后假装健康。
11. SIGINT/SIGTERM 优雅退出，停止任务、关闭连接、清理路由和 TUN。
12. online/last_seen 使用 TTL 或 lease 语义，断开的设备不能永久显示 online。

Stage 3 验收：

- control 停止 15 秒再启动，两个 daemon 在限定时间内自动恢复。
- relay 停止并恢复，daemon 自动重连。
- direct UDP 被防火墙阻断后 ping 通过 Relay 恢复。
- 恢复 UDP 后 diagnostics 最终回到 direct。
- 24 小时测试中无持续任务泄漏、信令无限增长或快速重试日志风暴。

Stage 4：Relay 身份认证和资源保护

目标：Relay 可以部署到公网，但不能被匿名注册、node ID 抢占或简单流量攻击拖垮。

必须实现：

1. 提供正式 Relay server 可执行程序，不再只作为测试库存在。
2. Relay 注册必须携带控制面签发的短期 ticket：
   - 包含 node_id、network_id、audience、过期时间和允许的 relay region。
   - 使用标准签名或经过验证的 MAC 方案。
   - Relay 验证 ticket 后才注册 node ID。
   - ticket 不能跨 Relay audience、网络或过期后使用。
3. 同 node ID 重复连接采用明确策略；旧连接断开不能删除新连接的注册记录。
4. 只允许同一 network_id 内转发。
5. Relay 传输使用 TLS，或在文档和部署配置中强制可信 TLS 终止层；不能默认公网明文。
6. 所有队列必须有界，并定义慢客户端策略。
7. 增加：
   - 最大 frame 大小。
   - 每连接发送速率和并发限制。
   - idle timeout、注册 timeout、keepalive。
   - 连接总数和每网络连接数限制。
   - 基础 metrics 和 health endpoint。
8. Relay 永远只转发端到端加密 payload，不解析或记录用户明文包。

Stage 4 必须测试：

- 无 ticket、错误签名、过期 ticket、错误 audience 注册失败。
- node A 不能注册为 node B。
- 不同网络不能互发数据。
- 重复 node ID 连接和断开不会破坏当前有效连接。
- 慢客户端或停止读取不会导致 Relay 无界内存增长。
- 超大 frame 和畸形 frame 被拒绝，服务进程保持健康。

Stage 5：加密实现决策与协议验证

这是安全门禁，不允许草率修改。

1. 先新增 docs/adr/0001-wireguard-engine.md，比较：
   - 当前自研实现。
   - 维护活跃、许可兼容、经过审计的用户态 WireGuard 实现。
   - Linux 内核 WireGuard + 本地 UDP/Relay 适配层。
2. 比较维度必须包含：
   - 维护状态和最近发布。
   - 安全审计和生产使用记录。
   - Linux/macOS/Windows 支持。
   - 自定义 direct/Relay packet transport 的可行性。
   - 性能、内存、许可证和升级风险。
3. 优先采用成熟实现，不要继续扩展自研密码协议。
4. 在替换完成前，至少给当前实现增加：
   - 官方 WireGuard/Noise 已知向量测试。
   - 标准 WireGuard 实现互操作测试。
   - 正确 TAI64N 编码和新鲜度/重放检查。
   - handshake MAC 验证。
   - cookie/DoS 策略或明确的限流替代方案。
   - session rekey/reject 时间测试。
5. 如果无法通过标准互操作测试，必须把协议命名为 P2WLAN experimental transport，禁止继续称为标准 WireGuard。
6. 不得以“自己的两端可以互通”作为标准协议正确性的证据。

Stage 5 验收：

- ADR 被提交并有可复核依据。
- 标准测试向量通过。
- 与外部标准实现的互操作结果有自动化测试或可复现记录。
- 任何安全降级都在 README 和 diagnostics 中明确标记。

Stage 6：部署、观测和性能基线

目标：用户可以安装、启动、升级、诊断和卸载 Linux 私测版。

必须实现：

1. 发布三个明确组件：
   - p2pnet-daemon
   - p2wlan-control
   - p2wlan-relay
2. 提供：
   - control/relay Dockerfile 和最小部署示例。
   - daemon systemd unit。
   - 安装、升级、卸载脚本。
   - 配置示例和首次加入网络文档。
   - checksum；有条件时增加制品签名。
3. daemon 尽量使用 CAP_NET_ADMIN，不默认要求整个进程永久以 root 运行；解释权限边界。
4. diagnostics 增加：
   - control 连接和最后成功时间。
   - assigned IP/CIDR 和路由状态。
   - session age/rekey 状态。
   - Relay 重连状态。
   - 最近错误，但不得包含 token、私钥和完整敏感材料。
5. 建立 benchmark/测试脚本并记录环境：
   - direct ping RTT overhead。
   - direct iperf3 throughput。
   - relay ping/throughput。
   - idle RSS 和 CPU。
   - 10/100 peers 内存增长。
   - direct -> relay 和 relay -> direct 时间。
   - control/relay 重启恢复时间。
6. 不要没有测量就宣称“高性能”或“低内存”。目标是先得到可重复基线，再优化热点。

六、暂时禁止扩展的范围

在 Stage 0-4 验收完成前，不要投入以下功能：

- 重做 React UI 或视觉设计。
- 完整 Magic DNS。
- 公网 TCP/UDP 端口映射。
- Relay 跨区域 mesh。
- 子网路由和 exit node。
- 移动端。
- macOS/Windows 安装包。
- 为了“看起来完整”而添加没有数据面的配置项。

可以修复跨平台编译，但不要让未实机验证的平台阻塞 Linux 私测版。

七、测试和证据要求

每个阶段完成后必须执行适用命令：

1. cargo fmt --all --check
2. cargo clippy --workspace --all-targets --all-features -- -D warnings
3. cargo test --workspace --all-targets
4. cd server && go test -race ./... -count=1 && go vet ./...
5. pnpm run build
6. pnpm audit --audit-level high
7. ./scripts/control-smoke.sh
8. Linux root 环境：P2WLAN_REQUIRE_TUN_SMOKE=1 ./scripts/tun-ping-smoke.sh
9. 新增的 security/reconnect/relay fallback smoke
10. git diff --check
11. git status --short --branch

真实 Linux 测试规则：

- 本地交叉编译 release 二进制，远端不编译 Rust。
- 上传 daemon/control/relay 制品到临时或明确版本路径。
- 测试前记录系统、架构、内存、内核、iptables/nftables 状态。
- 不破坏 Docker 或服务器已有防火墙规则。
- 添加的临时规则必须精确删除。
- 测试结束确认没有 p2wlan 进程、namespace、bridge、TUN、临时路由和防火墙规则残留。

真实双机最终验收：

- 必须是两个独立网络环境，不能只用同一主机两个 namespace 替代。
- 两端不手工指定虚拟 IP 和 overlay 路由。
- 验证 ping、TCP curl/SSH 和 iperf3。
- 验证 direct path。
- 阻断 peer direct UDP，验证 Relay ping。
- 恢复 UDP，验证回切 direct。
- 重启 control 和 relay，验证自动恢复。
- 如果没有第二台机器，报告 PENDING，并保留可执行脚本；不得宣称通过。

八、提交策略

建议提交顺序：

1. chore: establish strict quality gates
2. feat: configure managed tun address and routes
3. test: remove manual overlay setup from tun smoke
4. fix: allocate virtual addresses transactionally
5. feat: enforce network and device authorization
6. feat: authenticate device registration
7. feat: recover control and peer sessions after disconnect
8. feat: authenticate and bound relay sessions
9. docs: decide wireguard engine and document security status
10. chore: package linux private beta services

每次提交前只暂存本阶段相关文件。不要把本地数据库、配置私钥、日志、target、dist 或测试凭据提交进去。

九、每阶段汇报格式

必须输出：

- 阶段名称和提交哈希。
- 改动文件列表。
- 行为变化。
- 数据库或配置迁移说明。
- 实际运行过的命令和退出结果。
- mock/unit、namespace、单机真实 TUN、双机真实测试分别是什么状态。
- 安全影响和仍存在的风险。
- 未完成项及原因。
- 下一阶段计划。

不要只说“所有测试通过”。必须说明哪些测试、在哪个平台、是否需要 root、是否真实经过 TUN/direct/Relay。

十、立即开始

先执行开始前检查，输出简短审计结果，然后依次完成 Stage 0、Stage 1 和 Stage 2。每个 Stage 独立提交并完整验证。

Stage 0-2 完成后继续 Stage 3-6，但如果 Stage 5 的加密引擎选择需要重大架构改动，先提交 ADR 和可复现证据，不要在没有设计依据时仓促替换。

遇到外部基础设施缺失时继续完成所有本地可完成内容和自动化脚本，只把真正需要第二台主机、证书、域名或用户授权的步骤标记为 PENDING。
```

## 给执行 Agent 的验收底线

下面任一情况出现，都不能认为下一阶段完成：

- `--help` 仍会生成配置或创建 TUN。
- managed 模式仍需手工传 `--address`。
- TUN smoke 仍需脚本手工添加 overlay 路由。
- 任意登录用户仍能操作其他用户的设备、信令或隧道。
- Relay 仍允许匿名客户端声明任意 node ID。
- 控制面重启后 daemon 必须人工重启。
- ACL/DNS/端口映射只有结构体和单元测试，却被文档描述为已可用。
- 只跑同机 mock/namespace 测试，却宣称复杂 NAT 或真实双机已经通过。
- 自研加密协议没有标准向量和互操作测试，却宣称为生产级 WireGuard。
- 远端测试遗留进程、网卡、路由、namespace 或防火墙规则。

## 验收者说明

后续验收应优先检查行为和证据，而不是提交数量。建议重新执行所有本地命令，并在独立 Linux 环境复测：自动地址、自动路由、direct、Relay fallback、恢复切换、控制面重启、Relay 重启和越权攻击用例。

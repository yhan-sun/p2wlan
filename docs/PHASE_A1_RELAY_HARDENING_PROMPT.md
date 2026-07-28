# Phase A1 Coding Agent 提示词：Relay 资源边界与协议契约

Status: Ready for implementation  
Baseline: `b304795 feat: improve direct UDP traversal`  
Parent plan: [ENGINE_OPTIMIZATION_PLAN.md](ENGINE_OPTIMIZATION_PLAN.md)

下面代码块中的内容可以直接交给一个具备仓库读写和终端能力的 Coding Agent。本批次只完成 Phase A1，完成后停止，由验收者复核后再开始 Relay ticket/TLS 和 Probe v2。

```text
你是一名资深 Rust/Go 网络系统工程师和安全工程师。请在当前 P2WLAN 仓库中实现 Phase A1：Relay 资源边界与协议契约。

这是一项代码实现任务，不是方案讨论。你必须阅读现有实现、修改代码、增加测试、运行验证，并报告实际结果。不要实现本提示词明确排除的后续阶段。

一、仓库和基线

仓库：yhan-sun/p2wlan
期望基线提交：b304795 feat: improve direct UDP traversal

验收者可能已经在工作区新增或修改以下文档：

- README.md
- docs/ROADMAP.md
- docs/ENGINE_OPTIMIZATION_PLAN.md
- docs/PHASE_A1_RELAY_HARDENING_PROMPT.md

这些改动属于验收者。不得回滚、覆盖或把它们混入你的实现提交。工作区不干净不是执行 git reset、git checkout 或删除文件的理由。只暂存你为 Phase A1 修改的文件。

二、开始前必须阅读

文档：

- README.md
- docs/ENGINE_OPTIMIZATION_PLAN.md，尤其第 4、6、9、13、14、16、19 节
- docs/PROTOCOL.md
- docs/ROADMAP.md

代码：

- client/relay/src/protocol.rs
- client/relay/src/error.rs
- client/relay/src/client.rs
- client/relay/src/server.rs
- client/relay/src/lib.rs
- client/daemon/src/relay.rs
- client/daemon/src/peer.rs
- client/daemon/src/diagnostics.rs
- server/relay/main.go
- server/relay/main_test.go（如果不存在，确认后创建）

先执行并记录：

- git status --short --branch
- git rev-parse --short HEAD
- rg -n "unbounded_channel|UnboundedSender|UnboundedReceiver" client/relay
- cargo fmt --all --check
- cargo test --workspace --all-targets
- cd server && go test -race ./... -count=1 && go vet ./...

不要因为已有测试较多就跳过基线。若基线失败，先判断是否与本任务相关；不得隐瞒。

验收者在 2026-07-20 的 macOS 基线结果：

- `cargo fmt --all --check`：通过。
- `cargo test --workspace --all-targets`：通过。
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`：通过。
- `cd server && go test -race ./... -count=1 && go vet ./...`：通过。
- `pnpm run build`：通过，有现存 Vite dynamic/static import warning。
- `./scripts/control-smoke.sh`：失败。两端已注册、安装 WireGuard session 且进入 Direct，但脚本要求双方都出现 `Sent ... UDP punch probes`；当前 responder 可以通过收到对端 Probe 确认 Direct，因此只在一端出现该日志。该已知断言问题不属于 A1，不得为通过 A1 而修改 NAT 状态机或伪造日志。

三、当前真实问题

1. Rust Relay server 为每个 peer 使用 `mpsc::unbounded_channel<Vec<u8>>`。慢客户端可以让转发数据无限积压。
2. Rust Relay client 的命令和接收通道也是 unbounded，调用方持续发送或不消费接收消息时可以无限增长。
3. Go Relay 的 peer send channel 已有固定容量且重复 node ID 的注销检查基本正确，不要把它误报为完全缺失；但容量、超时和限制仍是硬编码或不完整的。
4. Rust Relay 的重复 node ID 注册使用简单覆盖。旧连接退出时可能删除或影响新连接，必须建立连接所有权语义。
5. Relay 注册、空闲连接、frame 和错误缺少统一、可配置的资源边界与稳定原因码。
6. Relay 目前仍是明文 TCP 和匿名 node ID 注册。Phase A1 不能把它描述为公网安全；ticket、network isolation 和 TLS 属于紧接着的 Phase A2。

四、本批次目标

完成后必须满足：

- Rust Relay crate 中不再使用 unbounded mpsc channel。
- Rust 和 Go Relay 都有显式配置的有界队列、注册超时、空闲超时、最大连接数和最大 frame payload。
- 慢客户端不能导致无界内存增长；队列满时行为确定、可测试、可诊断。
- 重复 node ID 连接的替换和清理不会让旧连接删除新连接。
- 协议错误和本地 Relay 失败使用稳定 code，而不是要求上层解析英文字符串。
- 当前正常注册、Ping/Pong、双向加密 payload 转发和 daemon Relay fallback 行为不回归。
- 文档明确标注：完成 A1 后 Relay 仍未完成身份认证和 TLS，不能作为公网安全版本验收。

五、必须实现

### A1.1 统一限制配置

Rust 新增清晰的 Relay server/client limits 配置。可以拆为 `RelayServerConfig`、`RelayClientConfig`、`RelayLimits`，但不要制造无意义抽象。至少包含：

- outbound queue capacity，必须大于 0。
- inbound/client message queue capacity，必须大于 0。
- register timeout。
- idle timeout。
- maximum connections。
- maximum frame payload；不得超过当前 u16 wire length 的协议上限。
- keepalive interval 如已存在，应纳入 client config，并验证与 idle timeout 的关系。

默认值必须集中定义、保守、可在测试中用小值覆盖。非法配置在 start/connect 前返回明确错误，不能运行到一半才 panic。

Go Relay 增加等价的运行参数或 config struct，并为 CLI flag/environment 提供明确入口。不要改变现有默认监听地址。至少支持：

- send queue capacity。
- register timeout。
- idle timeout。
- maximum connections。
- maximum frame payload。

不要在每个 frame 路径重复读取环境变量。

### A1.2 Rust 全部有界通道

替换 `client/relay` 中所有 `mpsc::unbounded_channel`、`UnboundedSender`、`UnboundedReceiver`。

要求：

- 数据面发送不能无限等待导致 daemon 主循环永久阻塞。
- 队列满时使用明确 backpressure 策略：返回可识别错误，或者关闭该慢连接；不同通道可以采用不同策略，但必须在代码和测试中解释。
- 不允许用 `let _ = sender.send(...)` 静默吞掉 queue full/closed。
- 如果公共方法从同步变成 async 或返回值变化，更新所有调用方和测试，保持错误可传播到 diagnostics。
- 不得通过把容量设成极大值来规避设计。

### A1.3 慢客户端策略

Relay server 向某 peer 的 outbound queue 满时，必须执行一种确定策略：

推荐：将目标 peer 标记为 slow consumer，关闭目标连接，并向发送方返回稳定的 `PEER_BACKPRESSURE` 或等价错误。允许选择“只丢当前 datagram”，但必须证明不会造成日志风暴或永久黑洞，并给出指标/诊断依据。

要求：

- Rust 和 Go 行为尽可能一致。
- 不记录或输出加密 payload 内容。
- 错误响应本身也不能因为队列满而形成无限重试。
- 测试必须用很小的 queue capacity 确定性触发，不得依赖向系统发送数 GB 数据。

### A1.4 连接所有权与重复注册

为每个 Relay 连接分配不可复用的 connection generation/ID，或使用等价的所有权比较。

语义：

- 同 node ID 新连接注册成功后，旧连接被关闭或替换。
- 旧连接的 defer/drop/unregister 只能删除仍属于自己的表项。
- 旧连接稍后退出不能删除新连接。
- 同一连接重复注册为另一个 node ID 必须被拒绝，或先安全注销旧 ID；不能同时占用两个 ID。
- Rust 与 Go 都必须有覆盖此竞态的测试。Go 已有指针所有权检查时，补足测试，不要为了形式重写正确代码。

### A1.5 注册、空闲和连接上限

- 新 TCP 连接必须在 register timeout 内完成合法注册，否则关闭。
- 已注册连接超过 idle timeout 且没有合法 frame/keepalive 时关闭。
- 超过 maximum connections 时立即拒绝或关闭新连接，并输出稳定原因。
- timeout 测试使用暂停时间、短测试时限或 deadline，不允许测试 sleep 数十秒。
- 连接计数在错误、取消、重复注册和正常关闭后都必须正确归还。

### A1.6 Frame 读取边界

- 在分配 payload buffer 前检查声明长度是否超过 configured maximum frame payload。
- 畸形 magic、unsupported version、超长 frame、截断 frame 和非法 UTF-8 node ID 必须产生稳定协议错误并关闭或拒绝。
- 不要把所有解析失败伪装成 `io.ErrUnexpectedEOF`。
- wire protocol v1 的合法 frame 必须继续兼容；本批次不要增加 ticket 字段或提升协议版本。

### A1.7 稳定原因码

在协议/错误层定义枚举或常量，至少覆盖：

- `INVALID_FRAME`
- `UNSUPPORTED_VERSION`
- `REGISTRATION_REQUIRED`
- `REGISTRATION_TIMEOUT`
- `DUPLICATE_REGISTRATION`
- `CONNECTION_LIMIT`
- `FRAME_TOO_LARGE`
- `PEER_NOT_FOUND`
- `PEER_BACKPRESSURE`
- `IDLE_TIMEOUT`
- `TRANSPORT_CLOSED`

要求：

- wire error code 使用稳定整数；Rust 和 Go 必须共享同一映射并有兼容测试或测试向量。
- daemon diagnostics 使用稳定 snake_case code；人类可读 message 只用于展示。
- 禁止上层通过 `err.contains("...")` 判断上述新增 Relay 状态。
- 保留未知 code 的 forward-compatible 表达，旧客户端不能因未知 code panic。

### A1.8 文档和测试向量

更新 `docs/PROTOCOL.md`，增加 Relay v1 当前 frame、错误码、资源限制、重复注册和慢客户端语义。必须明确写出：

- v1 注册仍只有 node ID，尚未认证。
- v1 TCP 尚未提供 TLS。
- A1 是资源安全和协议契约，不是公网安全完成状态。
- Phase A2 将增加 Relay ticket、network binding 和 TLS。

新增一个 Rust/Go 都能读取或各自固定复制并严格比较的最小协议测试向量，覆盖至少：

- registered frame。
- peer-not-found error frame。
- frame-too-large 的 header/拒绝行为。
- unknown error code 解码。

不要为了共享测试向量引入构建时跨语言代码生成系统。

六、明确排除

本批次禁止实现：

- Relay JWT/ticket 签发和验证。
- TLS/rustls、证书生成或证书部署。
- network_id 隔离和跨网络转发授权。
- Punch/ACK v2、X25519 临时密钥或 probe MAC。
- 控制面 WebSocket/SSE/QUIC 改造。
- NAT Prediction、Birthday、Socket Pool。
- Engine crate 提炼。
- UI 重构。

这些内容将在 A1 验收后分别进入 A2/A3。不要顺手实现，否则验收者将要求拆分或拒收。

七、必须新增的测试

Rust：

- 非法 limits/config 被拒绝。
- client command queue 和 inbound queue 有界。
- server outbound queue 满时触发指定策略。
- register timeout。
- idle timeout。
- maximum connections 回收正确。
- 声明超长 frame 在分配 payload 前被拒绝。
- 同 node ID 新连接替换旧连接后，旧连接退出不删除新连接。
- 同连接重复注册行为符合约定。
- 未知 wire error code 可解析且不 panic。
- 正常双向转发、Ping/Pong 和 keepalive 不回归。

Go：

- flags/config 非法值启动失败。
- send queue 满时执行确定策略。
- register timeout、idle timeout、maximum connections。
- frame size 边界。
- 重复 node ID 竞态和旧连接注销安全。
- Rust/Go error code 和测试向量一致。

测试不得只断言日志文本。测试必须有超时保护，失败时不能无限挂起。

八、实现约束

- 不使用 `unsafe` 解决本任务。
- 不自研加密算法；本批次本来也不需要新增密码依赖。
- 不添加未使用的 token/TLS 依赖。
- 不使用无界 channel、无限 VecDeque 或后台无限重试替代原问题。
- 不使用 shell 字符串拼接执行命令。
- 不打印 token、私钥或用户加密 payload。
- 新增依赖前说明必要性；本任务原则上不需要大型依赖。
- 保持 macOS、Windows、Linux 的 Rust 编译边界。
- 不修改生成物、`target/`、`dist/`、数据库、日志或本机配置。
- 不回滚验收者的未提交文档改动。

九、验证命令

完成后必须实际运行：

1. cargo fmt --all --check
2. cargo clippy --workspace --all-targets --all-features -- -D warnings
3. cargo test -p p2pnet-relay --all-targets
4. cargo test --workspace --all-targets
5. cd server && go test -race ./... -count=1
6. cd server && go vet ./...
7. pnpm run build
8. ./scripts/control-smoke.sh（运行并与上述已知基线比较；同一断言失败暂不阻塞 A1，任何新增失败都阻塞）
9. git diff --check
10. rg -n "unbounded_channel|UnboundedSender|UnboundedReceiver" client/relay
11. git status --short --branch

第 10 条必须没有结果。若某命令因当前机器权限或外部基础设施无法运行，明确标记 PENDING；本批次的 unit/integration tests 不需要 root，不能以缺少 root 为理由跳过。不要在 A1 提交中修改 `scripts/control-smoke.sh`，其现存断言问题由验收者单独处理。

十、提交要求

完成并通过验证后，创建一个独立提交：

`fix: bound relay resources and stabilize errors`

只暂存 Phase A1 实现和对应协议文档，不要暂存验收者预先存在的架构文档改动，不要 push，不要 rebase，不要改写历史。

十一、完成汇报格式

必须报告：

- 提交哈希。
- 改动文件列表。
- Rust/Go 的 queue full、duplicate registration、timeout 具体语义。
- 新增的稳定 error code 映射。
- 每条验证命令的退出状态和测试数量。
- 哪些是真实 socket 集成测试，哪些只是 unit test。
- 未完成/PENDING 项。
- 当前剩余安全风险，必须明确包含“匿名 node ID 注册”和“明文 TCP”。

不要只说“测试全部通过”，不要宣称 Phase A 或 Relay 安全加固已经全部完成。完成 A1 后停止，等待验收者复核。
```

## 验收者检查清单

收到实现后，验收者至少执行：

- 检查提交是否只包含 A1 范围。
- 搜索 `client/relay` 是否仍有无界 channel。
- 人工检查 queue full 是否会死锁、递归报错或静默丢失。
- 人工检查旧连接退出是否可能删除新连接。
- 人工检查 frame 长度是否在内存分配之前校验。
- 对照 Rust/Go 原始字节检查 error frame 测试向量。
- 重新执行提示词第九节全部命令。
- 拒绝任何把 A1 描述为“Relay 已安全可部署公网”的文档或输出。

通过 A1 后，下一批是 Phase A2：Relay EdDSA ticket、network binding、TLS 和密钥轮换。

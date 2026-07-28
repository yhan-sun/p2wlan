# Phase A2 Coding Agent 提示词：Relay Ticket、网络隔离、TLS 与密钥轮换

Status: Ready for implementation  
Baseline: `4eef998 test: bound relay cleanup EOF wait`  
Applies to: P2WLAN 0.1.24 and later

## 使用方式

下面代码块中的内容可以直接交给具备仓库读写和终端能力的 Coding Agent。本批次只完成 Phase A2。完成后停止，由验收者复核后再进入 Phase A3 认证 Probe v2。

```text
你是一名资深 Rust/Go 网络系统工程师和安全工程师。请在当前 P2WLAN 仓库中实现 Phase A2：Relay EdDSA ticket、network binding、TLS 和签名密钥轮换。

这是一份实现与验收合同，不是架构头脑风暴。你必须阅读现有实现、修改代码、补齐协议文档、运行测试并提交代码。不要只输出方案，不要跳过失败路径和跨语言兼容验证。

一、仓库与基线

仓库：yhan-sun/p2wlan
分支：main
开始基线不得早于：

4eef998 test: bound relay cleanup EOF wait

Phase A1 已完成并验收：

- Rust/Go Relay frame V1 契约和稳定 wire error code。
- 所有 Relay 队列有界，慢消费者策略明确。
- 注册、空闲、连接数和 frame 大小有资源上限。
- 重复 node ID 使用连接代际/指针所有权保护。
- Rust/Go server shutdown 会回收连接、任务和 peer mapping。
- Rust RelayClient 有 bounded command/inbound queue、keepalive 和 idle timeout。

不要重做或撤销 A1。A2 必须建立在 A1 的资源边界上。

当前工作区可能包含验收者的未提交改动，包括但不限于：

- README.md
- docs/ROADMAP.md
- docs/ENGINE_OPTIMIZATION_PLAN.md
- docs/PHASE_A1_RELAY_HARDENING_PROMPT.md
- docs/PHASE_A2_RELAY_SECURITY_PROMPT.md
- server/auth/auth.go 中既有的空白/换行修正

这些改动属于验收者。不得 git reset、git checkout、覆盖、删除或把无关改动混入 A2 提交。若 A2 可以通过新增独立文件避免修改已有脏文件，应优先这样做；若确实必须修改重叠文件，先理解并保留原改动，只暂存 A2 所需内容。

二、开始前必须阅读

1. 文档：

- README.md
- docs/PROTOCOL.md
- docs/ROADMAP.md
- docs/ENGINE_OPTIMIZATION_PLAN.md
- docs/PHASE_A1_RELAY_HARDENING_PROMPT.md
- docs/NEXT_PHASE_IMPLEMENTATION_PROMPT.md 的 Relay 身份认证部分

2. Rust：

- client/crypto/src/sign.rs
- client/daemon/src/config.rs
- client/daemon/src/control.rs
- client/daemon/src/relay.rs
- client/daemon/src/lib.rs 中 Relay supervisor/selection 调用点
- client/relay/src/protocol.rs
- client/relay/src/error.rs
- client/relay/src/lib.rs
- client/relay/src/client.rs
- client/relay/src/server.rs

3. Go：

- server/main.go
- server/auth/auth.go
- server/api/api.go
- server/database/database.go
- server/database/stage2_test.go
- server/relay/main.go
- server/relay/main_test.go
- server/go.mod

4. 脚本与部署：

- scripts/control-smoke.sh
- 仓库中所有启动 control/relay 的 Docker、systemd、release 或 smoke 配置

三、修改前基线

先运行并记录，不要为了得到绿色基线而修改代码：

git status --short --branch
git log -1 --oneline
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets
cd server && go test -race ./... -count=1
cd server && go vet ./...
./scripts/control-smoke.sh

若 GOROOT 被本机环境错误覆盖，可在确认 Homebrew/系统 Go 安装完整后使用 `env -u GOROOT go ...`，但必须在报告中说明。不得把工具链错误描述成代码失败或伪造通过结果。

四、A2 安全目标

A2 完成后必须满足：

1. 公网模式下，没有控制面签发的有效短期 ticket，连接不能注册 Relay。
2. 客户端不能用自己的 ticket 注册成另一个 node ID。
3. ticket 不能跨 network、Relay audience、region 或过期后使用。
4. Relay 路由和查找以 `(network_id, node_id)` 为身份键，不同 network 绝不能互相转发。
5. Rust 和 Go Relay 默认使用经过证书验证的 TLS 1.3；明文只能在显式开发配置下使用，不得自动降级。
6. ticket 签名使用标准 EdDSA/Ed25519，严格校验 `alg` 和 `kid`，支持当前及上一把验证公钥共存。
7. ticket 不落盘、不进入日志、diagnostics、panic 或错误响应。
8. 删除设备、撤销 device credential 后不能再签发 ticket；已签发 ticket 的最长残留权限由短 TTL 明确限制。
9. A1 的 frame、队列、timeout、shutdown、duplicate registration 和错误码行为不能回归。

注意：A2 提供的是 Relay 传输和注册安全，不代表整个 P2WLAN 已完成安全审计。现有 Punch/ACK 仍未认证，属于 A3。

五、固定的协议与密码决策

不要另选自定义 token、MAC token、PASETO 或自制二进制签名格式。本批次固定使用：

- token 格式：标准 JWT Compact Serialization。
- 签名算法：EdDSA，具体为 Ed25519。
- JOSE header：`alg` 必须严格等于 `EdDSA`；`typ` 固定为 `p2wlan-relay+jwt`；必须包含非空 `kid`。
- 控制面持有 Ed25519 私钥并签发；Relay 只配置公钥 keyring。
- 禁止接受 `none`、HS256、算法自动选择或由 token 决定任意 key 类型。
- 使用成熟库：Go 复用 `github.com/golang-jwt/jwt/v5`；Rust 使用维护中的 JWT/JOSE 库及 Ed25519 验证实现。不要手写 base64url、JSON 拼接或签名验证。

RelayTicketClaims 必须包含：

- `iss`: 固定 `p2wlan-control`。
- `sub`: 服务端 device ID。
- `aud`: 精确的 Relay audience，单值，不接受模糊前缀或通配符。
- `iat`: 签发时间。
- `nbf`: 不早于时间。
- `exp`: 过期时间。
- `jti`: 至少 128 bit CSPRNG 随机值的无歧义编码。
- `device_id`: 必须等于 `sub`。
- `network_id`: 来自数据库中的 device，不接受客户端自由填写。
- `node_id`: 当前控制面分配的 node ID；在本仓库中通常等于 device ID，但仍保留独立字段并验证一致性。
- `relay_region`: 目标 Relay region。
- `relay_protocol`: 固定为 1。

默认 ticket TTL 为 5 分钟，可配置范围 30 秒到 15 分钟。验证允许的时钟偏差默认 30 秒且可设置更小，禁止无限 leeway。时间验证必须支持注入 clock，测试不能依赖真实等待或固定历史时间。

六、控制面签发

### A2.1 Relay catalog

控制面必须有结构化 Relay catalog，而不是让客户端任意请求 audience。建议增加清晰的配置模型：

RelayDescriptor {
    region: String,
    audience: String,
    endpoint: String,
}

要求：

- `endpoint` 使用 `tls://host:port`；仅显式开发配置可使用 `tcp://host:port`。
- `audience` 是部署者配置的稳定逻辑 ID，例如 `relay-sg-1`，不能从不可信 Host header 推导。
- region、audience、endpoint 均非空；audience 唯一；重复或非法配置启动失败。
- 可以新增 `RELAY_CATALOG_JSON` 或等价的单次结构化配置解析。
- 现有 `RELAY_SERVERS` 可作为显式 legacy/dev 兼容输入，但不能用于默认公网安全模式，也不能允许任意 audience 签发。
- 设备注册响应增加可选 `relay_catalog`，保留旧 `relay_servers` 字段用于旧客户端兼容。新客户端优先使用 catalog。

### A2.2 Ticket endpoint

新增：

POST /api/v1/relay/tickets

该接口必须只接受有效 device credential，不接受普通用户 JWT fallback。请求至少包含：

{
  "audience": "relay-sg-1",
  "region": "sg"
}

响应至少包含：

{
  "ticket": "<compact JWT>",
  "expires_at": 1234567890,
  "audience": "relay-sg-1",
  "region": "sg"
}

签发流程：

1. 从认证 context 取得 device claims。
2. 再从数据库读取 device 当前状态，确认 device 存在、credential 未撤销/过期、network 未变化。
3. audience/region 必须精确匹配服务端 catalog 中同一条 Relay。
4. `device_id`、`network_id`、`node_id` 全部从服务端可信状态构造。
5. 使用当前 active `kid` 的 Ed25519 私钥签发。
6. 对接口使用现有 body limit，并增加合理的单设备速率限制；不得产生无限 ticket。
7. HTTP 错误返回稳定、非敏感 code；不得回显 ticket、签名、私钥路径或内部 JWT parse error。

建议在 `server/auth/relay_ticket.go` 或边界清晰的新 package 实现 signer/verifier，避免把 user JWT、device credential 和 Relay ticket 混成同一种 token。

### A2.3 签名密钥配置与轮换

控制面 signer 配置必须包含 active `kid` 和对应 Ed25519 private key。Relay verifier 配置必须支持 `kid -> Ed25519 public key` 的只读 keyring。

要求：

- key 使用 PEM/PKCS#8 或成熟库直接支持的标准编码，不在环境变量中放原始私钥正文。
- 私钥文件无法读取、权限/格式错误或公私钥不匹配时，安全模式启动失败。
- Relay 遇到未知 `kid` 必须拒绝，不尝试所有 key 猜测验证。
- keyring 至少可同时加载 current 和 previous 两把公钥。
- A2 不要求进程内热加载；允许通过有序重启生效，但文档必须给出固定顺序：先把新 public key 部署到所有 Relay，再切换 control active signer，等待 `max_ticket_ttl + clock_skew`，最后删除旧 public key。
- 删除旧 key 后，旧 `kid` ticket 必须被拒绝。
- 日志最多输出 `kid` 和 public key fingerprint，绝不输出私钥或完整 ticket。

即时全局撤销列表不属于 A2。A2 的撤销边界是：撤销 device credential/删除 device 后停止签发，已签 ticket 最迟在短 TTL 到期时失效。必须在文档明确该窗口。

七、Relay wire 协议与注册状态机

### A2.4 Authenticated Register frame

保留 A1 的 8-byte frame header 和 Relay Protocol V1，不要为了 A2 重写整个 framing。新增独立消息类型：

MSG_AUTH_REGISTER = 0x09

payload 使用严格二进制布局：

u8  node_id_len
byte node_id[node_id_len]
u16 ticket_len (big endian)
byte ticket[ticket_len]

约束：

- node_id_len 必须为 1..255。
- node_id 必须是合法 UTF-8，且满足当前 node ID 约束。
- ticket_len 必须大于 0，并设置独立保守上限，建议 8 KiB；总 payload 仍受 A1 `max_frame_payload` 限制。
- payload 必须精确消费，不接受 trailing bytes、截断或长度溢出。
- ticket 必须在插入 peer table/hub 之前完成全部验证。
- ticket `node_id` 必须常量时间无要求地做精确字符串相等比较；不允许请求 node ID 覆盖 ticket 身份。
- ticket audience 和 region 必须匹配当前 Relay 实例配置。
- 当前时间达到 `exp` 后连接必须被服务端关闭；不能让一次短期 ticket 创建无限会话。

旧 `MSG_REGISTER = 0x01`：

- 安全模式默认返回 `ERR_AUTH_REQUIRED` 并关闭。
- 只有服务端显式 `allow_legacy_unauthenticated=true` 的开发模式可以接受。
- 明文 transport 和匿名 register 是两个独立开关，均默认 false；不得因为启用一个而隐式启用另一个。
- 客户端不得在认证注册失败后自动回退匿名注册。

增加并同步 Rust/Go 的稳定错误码：

- 4011 `auth_required`
- 4012 `invalid_ticket`
- 4013 `ticket_expired`
- 4014 `audience_mismatch`
- 4015 `identity_mismatch`
- 4016 `network_mismatch`
- 4017 `ticket_not_yet_valid`
- 4018 `unknown_ticket_key`

外部错误不得包含原始 token 或底层密码库细节。未知 code 仍按 A1 规则安全解析。

### A2.5 Network binding

Rust 和 Go Relay 的注册表都必须从单一 `node_id` key 改为等价于：

(network_id, node_id) -> authenticated connection

要求：

- peer 连接对象保存经过验证的 device_id、network_id、node_id、audience、region、ticket expiry、jti/kid（仅非敏感标识）。
- forward 的 source 身份只能来自已认证连接对象，不读取客户端声明的 source。
- destination 只在 source 的 network_id 内查找。
- 不同 network 中相同 node_id 可以同时注册，互不替换、互不注销。
- 跨 network 目标对发送方表现为普通 peer-not-found，避免泄漏另一个网络是否存在该 node ID。
- duplicate replacement 和 cleanup 必须比较完整 network key 加连接代际/指针，旧连接不能删除新连接。
- 每网络连接数如未在 A1 实现，本批次增加保守、可配置上限；检查和占用必须原子化，关闭后正确回收。

八、TLS transport

### A2.6 客户端 endpoint 与 TLS

Rust Relay client 和 daemon 必须使用显式 scheme：

- `tls://relay.example.com:18081`
- `tcp://127.0.0.1:18081`，仅开发模式且配置明确允许

要求：

- 默认只允许 TLS。
- TLS 最低和最高版本固定为 TLS 1.3。
- 默认使用系统可信根；自托管允许配置额外 CA bundle/path。
- 必须验证证书链、有效期和 DNS server name/IP SAN。
- 禁止 `dangerous` 跳过验证、accept-any-certificate 或自动信任首次证书。
- 不得在 TLS handshake 失败后重试明文。
- DNS 解析、TCP connect、TLS handshake、认证注册分别有明确 timeout 和结构化错误 code。
- endpoint parser 必须正确处理 DNS、IPv4 和带方括号的 IPv6。
- ticket 和 TLS server name/audience 是不同概念，二者都必须分别验证。

可以引入 `rustls`、`tokio-rustls`、`rustls-native-certs`、`rustls-pemfile` 等成熟依赖。测试证书可以运行时生成；不得提交生产私钥或长期测试 CA 私钥。

daemon 配置至少增加：

- `relay.allow_insecure_plaintext`，默认 false。
- 可选 `relay.ca_cert_path` 或等价配置。

旧配置反序列化必须明确迁移：无 scheme 的 endpoint 不得在公网模式静默视为明文。可以只在显式 legacy/dev flag 下解释为 tcp。

### A2.7 Rust/Go Relay server TLS

Rust test/server implementation 与 Go deployment Relay 都必须支持 TLS 1.3：

- 配置 certificate chain 和 private key 文件。
- 安全模式缺少 cert/key 或 ticket verifier keyring时启动失败。
- 明文 listener 只能通过显式 `allow_insecure_plaintext` 开启，日志清楚标记开发模式。
- TLS handshake 必须在注册 timeout/独立 handshake timeout 内完成，并受总连接数限制。
- 慢 TLS handshake 不能产生无限 goroutine/task 或绕过 semaphore/connection limit。
- shutdown 必须关闭正在 handshake 和已注册的 TLS connection。
- Go 优先使用标准库 `crypto/tls`；Rust 使用 rustls，不引入 OpenSSL 运行时依赖。

若支持由可信反向代理终止 TLS，必须是独立且显式的部署模式，并说明 Relay 如何确保到代理的链路只在受控网络内；不能把“文档建议上 TLS”当作代码默认安全。

九、daemon ticket 生命周期

### A2.8 Ticket provider

daemon 不得把 Relay ticket 写入 Config、磁盘或 diagnostics。新增边界清晰的 ticket provider：

- 使用现有 device credential 调用 `/api/v1/relay/tickets`。
- 每个 Relay audience/region 分别获取 ticket。
- 连接/重连前确保 ticket 在 refresh margin 后仍有效。
- 缓存仅在内存，缓存 key 至少包含 device、network、audience、region。
- 默认在 `exp - min(60s, ttl/5)` 前刷新；测试可注入 clock/短 TTL。
- 同一 key 的并发刷新要合并，不能形成请求风暴。
- 401/403 是永久认证失败，触发明确 `ReauthRequired`/diagnostics；超时和 5xx 使用现有有 jitter 退避。
- Relay 连接收到 ticket-expired 或到达本地 refresh deadline 后，由 supervisor 获取新 ticket 并重连；禁止回退匿名 Relay。
- 网络、device 或 control credential 变化时清除相关 ticket cache。

如果当前 supervisor 暂时无法做到无缝双连接替换，A2 可以采用有界的“关闭旧连接 -> 获取新 ticket -> 重连”，但必须测试自动恢复且不能让过期连接无限存活。active/hot-standby 无缝迁移属于后续 Phase D。

### A2.9 Diagnostics

增加稳定、无敏感信息的诊断原因：

- `relay_ticket_fetch_failed`
- `relay_ticket_rejected`
- `relay_ticket_expired`
- `relay_tls_handshake_failed`
- `relay_certificate_invalid`
- `relay_insecure_transport_disallowed`
- `relay_audience_mismatch`
- `relay_network_mismatch`

允许展示 audience、region、kid、expires_at 和 endpoint；禁止展示 ticket、Authorization header、私钥、完整签名或 device credential。

十、必须新增的测试

所有异步/网络测试必须有 timeout，失败不能永久挂起。时间相关测试使用 injected clock 或短可控 deadline，禁止 sleep 几分钟。

### Go control

- 只有 device credential 可以请求 Relay ticket，user JWT 被拒绝。
- ticket claims 来自数据库，不接受客户端伪造 device/network/node。
- 未配置 audience、region 不匹配和 revoked/expired credential 拒绝。
- EdDSA header 的 alg/typ/kid 正确。
- TTL、iat/nbf/exp 和 jti 边界正确。
- 非法 signer 配置启动失败。
- ticket endpoint rate limit 有确定测试。

### Rust ticket/protocol

- Auth Register encode/decode golden vectors。
- 截断、trailing bytes、空 ticket、超长 ticket 和非法 UTF-8 拒绝。
- 固定测试 Ed25519 key 和 injected clock 验证合法、篡改、过期、尚未生效、错误 audience、错误 region、错误 node、未知 kid。
- 未知 wire error code 不 panic。

### Rust Relay server/client

- 安全模式匿名 register 100% 拒绝。
- 有效 ticket 注册并正常 Ping/Pong、双向 encrypted payload 转发。
- node A ticket 不能注册为 node B。
- 不同 network 不能互发；同 node ID 在不同 network 可共存。
- ticket 到期后连接关闭并清理 mapping/connection permit。
- duplicate registration 和 shutdown 的 A1 所有权测试继续通过。
- TLS 正常握手、未知 CA、错误 hostname、过期/无效证书、明文连 TLS endpoint 均按预期失败。
- `tcp://` 未显式允许时在发起连接前失败。
- TLS handshake stall 受 timeout 和连接上限约束。

### Go Relay

- 与 Rust 相同的 ticket、network isolation、duplicate、expiry 和 TLS 语义。
- `go test -race` 下并发注册、过期断开、Close/Accept/TLS handshake 无竞态和泄漏。
- Rust/Go 共享 JWT fixture、Auth Register binary vectors 和 error code 表。
- 使用错误算法、未知 kid、错误签名和畸形 token 不 panic。

### daemon/integration

- ticket 只保存在内存，序列化 Config/diagnostics 不出现 token。
- 两个并发连接请求合并 ticket refresh。
- ticket 即将过期会刷新并自动重连。
- ticket endpoint 401 不快速重试，5xx/timeout 使用有界退避。
- 一个真实 Go Relay TLS 实例与两个 Rust RelayClient 使用控制面签发 ticket 完成同网络转发。
- 第三个不同 network 客户端无法访问前两个节点。
- 测试生成临时证书/keys，结束后回收进程、端口和临时文件。

共享 fixture 不得包含生产 secret。固定测试私钥只能放在明确的 testdata/fixture 中并标注 TEST ONLY；更推荐测试运行时生成 key，并对必须跨语言的向量使用固定公开测试种子和 injected clock。

十一、文档与部署

更新 docs/PROTOCOL.md，至少写清：

- JWT header 和完整 claim schema。
- canonical audience/region 语义。
- Auth Register byte layout 和长度限制。
- 注册状态机与 legacy 拒绝策略。
- `(network_id, node_id)` 路由隔离。
- ticket expiry 连接行为。
- 4011..4018 error code。
- TLS 1.3 和禁止静默降级。
- Rust/Go golden vectors。

新增或更新部署文档：

- control signer private key 生成和文件权限。
- Relay verifier public keyring 配置。
- TLS certificate/CA 配置。
- key rotation 的四步顺序。
- ticket TTL 和撤销残留窗口。
- 本地开发明文模式的显式开关和风险警告。
- 生产配置示例不得包含真实 key/token。

README/状态描述必须准确：A2 后 Relay 注册与 transport 达到本阶段安全基线，但认证 Probe v2、安全审计、即时撤销和完整生产运维仍未完成。

十二、明确非目标

本批次禁止顺手实现：

- Punch/ACK Probe v2、session MAC、nonce replay window；这是 A3。
- QUIC、HTTP/2 Relay、WebSocket Relay、Multipath 或 FEC。
- Engine crate 提炼。
- NAT prediction、birthday paradox、socket pool 或 NAT database。
- ACL、DNS、端口映射或 UI 重构。
- 自定义 CA 自动分发、ACME 客户端或证书自动续期系统。
- 在线 JWKS 拉取、全局即时 jti revocation service。
- 替换 WireGuard 数据面或修改其密码协议。

若为了测试必须增加很小的 helper，应保持在 A2 边界内。不要用额外功能扩大提交面。

十三、工程约束

- 不使用 `unsafe` 绕过验证。
- 不自研密码算法、JWT parser、base64url 或证书验证器。
- 不用字符串 contains 判断密码/协议错误类型。
- 对 claims、catalog、register payload 使用结构化类型和 parser。
- secret 类型的 Debug/Display 必须脱敏；避免 Clone 和长生命周期，适用时使用 zeroize/secrecy。
- 所有新增 channel、cache、map、请求并发和任务必须有界并由 supervisor 持有。
- 不在 async mutex guard 内执行网络 I/O 或文件 I/O。
- TLS/auth 失败不得触发明文/匿名 fallback。
- 不修改测试来掩盖协议错误；失败测试应修复根因。
- 每个网络测试都必须有 timeout 和 cleanup。
- 不提交证书私钥、control signer 私钥、ticket 或 device credential。
- 不强推、不 rebase、不改写历史、不 push。

十四、最终验证

必须执行并记录：

git diff --check
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets
cd server && gofmt -w <仅本次修改的 Go 文件>
cd server && go test -race ./... -count=1
cd server && go vet ./...
cd server && go test -race ./relay -count=20
./scripts/control-smoke.sh
rg -n "accept_invalid_certs|danger_accept|InsecureSkipVerify|alg.*none|unbounded_channel" client server
rg -n "ticket|Authorization|private_key|device_credential" client server
git status --short

说明：

- `InsecureSkipVerify` 搜索必须没有生产代码命中；测试若需要验证拒绝路径，也不应开启跳过证书验证。
- `unbounded_channel` 不得重新出现在 Relay 路径。
- secret 搜索需要人工检查每个命中，确认没有日志/diagnostics 泄漏，不能机械删除合法字段。
- control-smoke 若仍有 A1 文档记录的 responder Punch 日志断言问题，可标记已知基线；任何新增失败都阻塞 A2。
- 缺少外部 DNS/真实证书不影响本地 CA 集成测试，不得以此为理由跳过 TLS 测试。

十五、提交要求

只暂存 A2 实现、对应测试、协议和部署文档。不要暂存验收者已有的无关工作区改动。

建议按以下逻辑提交，若代码依赖使拆分后无法编译，可以合并为更少但仍清晰的提交：

1. `feat: add EdDSA relay ticket issuance and protocol contract`
2. `feat: enforce relay network binding and TLS transport`
3. `feat: integrate relay ticket refresh and security diagnostics`

提交前检查：

git diff --cached --name-only
git diff --cached --check

不要 push。不要创建 tag。不要修改版本号。完成后停止等待验收。

十六、完成报告格式

报告必须包含：

1. 实际修改文件和职责。
2. JWT claim/header、Auth Register 和 network key 的最终 wire 契约。
3. TLS client/server 配置和明文开发开关。
4. ticket 获取、缓存、刷新、过期断开的状态机。
5. key rotation 和撤销窗口。
6. Rust/Go 跨语言 fixture/测试覆盖。
7. 所有验证命令的真实结果。
8. 未运行或失败项及原因。
9. commit hash 和 `git status --short`。
10. 明确声明没有 push、没有提交 secret、没有混入无关文件。

不得只说“全部完成”。不得把 A2 描述为整个项目已经过安全审计或已完成公网生产运维。完成后停止，不要自行开始 A3。
```

## 验收者重点

A2 完成后，验收者至少应独立复核：

- JWT verifier 是否严格锁定 EdDSA、typ、kid、issuer、audience 和全部时间声明。
- ticket 请求是否只能从可信 device context 生成 claims。
- 是否存在 TLS/认证失败后回退明文或匿名注册的路径。
- Relay map 是否真正以 `(network_id, node_id)` 隔离，跨网络测试是否能在删除隔离逻辑后失败。
- ticket expiry 是否会关闭连接并回收 mapping、permit、task/goroutine。
- TLS handshake 是否在 connection limit 内且 shutdown 可回收。
- key rotation 测试是否覆盖 current/previous/unknown/removed kid。
- daemon 是否会泄漏 ticket 到 Config、日志或 diagnostics。
- 所有网络测试是否有 timeout，race/Clippy 是否真实通过。
- 提交是否只包含 A2，是否错误提交了生产 key、证书或 token。

通过 A2 后，下一批是 Phase A3：认证 Probe v2、session-bound MAC、nonce replay window、来源/session 限速和跨版本迁移。

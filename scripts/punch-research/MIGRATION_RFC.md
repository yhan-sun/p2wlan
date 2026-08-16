# MIGRATION_RFC.md — UU 远程 NAT 打洞算法 → p2wlan Rust 迁移蓝图（S7）

- 状态：Draft（待 Gate1 验收后评审）
- 依据：
  - `/Users/pyu/Downloads/README.md`（UU 远程 v4.35.0 逆向协议，算法唯一依据）
  - `scripts/punch-research/`（本次研究工程化验证成果：puncher.py / predict.py / fingerprint.py / nat_sim.py）
  - p2wlan 现状调研（见「现状对照表」）

## 1. 现状对照表

| 能力 | p2wlan 现状 | punch-research 验证成果 | 差距 |
|---|---|---|---|
| NAT 检测 | `client/nat/src/detection.rs`：单 socket 双 STUN 服务器端口比较（简化法）；`detect_full`（RFC 3489）备选未启用 | 行为分类三轴（mapping/allocation/filtering）+ 四态映射 {ei,ad,apd,unknown}，多源交叉注入准确率 100%（fingerprint.py 单测 48/48） | 生产未走 detect_full；无 filtering 三态/全交叉探测 |
| 端口预测 | `client/nat/src/mapping.rs`：PortModelKind{FixedStep,Linear,NoisyLinear,MonotonicWindow,Periodic,Stable}，predict_ports 窗口 24/96 | predict.py：双向窗口 predict_ports、StepLearner（EWMA 0.6/0.4）、ReverseDetector（forward/reverse/mixed）、BirthdayPool（cap 128）、BudgetScanner 四段预算 | 已有主体，缺：反向/漂移检测、双窗口双向、池化散射调度、预算拆分回退链 |
| 打洞 | `direct_runtime/hole_punch.rs` + `udp/outbound.rs`：PUNCH/ACK 14B、同步 punch_at、fresh-mapping 预测并发、PunchSocketPolicy 散射 | 7 策略表 + 三层预算回退（exact→window→random→sweep）、三态防火墙判定、hairpin 探测、drift 重预测 | 缺：预测失败逐级回退预算、防火墙三态接入散射决策 |
| 生命周期 | candidate_refresh 15s 周期、3s 快重试、volatile 防抖 500ms、keepalive 25s 建议 | 参数化 keepalive、漂移检测+重预测、pair 缓存热启动（ttl+pattern）、事件时间线 | 缺：漂移检测接入 refresh 循环、缓存热启动协议化 |
| 信令 | nat_type ≤128B 字符串 hint（R1a 起 `p2v2:m=..;a=..;d=..;c=..;f=..;h=..`）；server 纯存储透传（dumb pipe，不解析） | 无（研究仅客户端视角） | 缺：预测窗口向量下发（f=/h= 已结构化，R1a；active filtering 探测 R1b） |
| 环境 | netenv.rs 仅代理/TUN 捕获 | 无新增（检测链路在 nat 探测中） | 无 |
| 验证 | mock/ 仅有 Rust harness 冒烟 | nat_sim.py 双 NAT 全谱模拟（4×3×3 注入）+ 36 组回归 + 324 格网格校准 | 迁移后需同一测试向量回放 |

## 2. 迁移范围与落点（Phase R1-R4）

### R1 信令 schema 升级 + 散射决策结构化消费（低风险，独立）

**R1a（本次已完成 ✅）**：把对端 NAT 行为指纹**结构化下发**给 peer，让散射决策从「看 `a=`」升级为「看 `m=`/`a=`/`f=`」；服务端仍纯透传（dumb pipe 是特性，非缺陷）。

- [x] `control_label()`（`client/nat/src/ice.rs`）升级 `p2:` → `p2v2:m=..;a=..;d=..;c=..;f=..;h=..`。`m=/a=/d=/c=` 逐字节不变（旧 client `.contains()` 零回归），`f=/h=` 用 serde 名新增。
- [x] 收端解析器 `parse_nat_hint` + `NatFingerprintHint` + `NatAllocation`（同 `ice.rs`，re-export 于 `lib.rs`）。纯函数、前缀无关（`p2:`/`p2v2:`）、损坏/裸词 → `parsed=false`。
- [x] 散射决策 `scatter_decision` + `legacy_nat_classifier`（`client/daemon/src/peer/connection/nat_hint.rs`）：`remote_nat_requires_port_scatter` 瘦身为薄委托，6 个消费点（candidates.rs:153/594/826 + probe_targets.rs:131/615/914）全部经单一函数。`parsed=false` 时逐字节回退 legacy 5-pattern。
- [x] Go 服务端 `UpdateDeviceEndpoint` cap `64 → 128`（`server/api/device_handlers.go`，**仅 1 常量**）；仍不解析、纯透传。2 条长度测试。
- [x] CLI 对端诊断结构化展示（`peer_nat_hint_summary`，`formatting/peer/utils.rs`）：`nat= m/.. a/.. f/.. h/.. scatter=yes|no`，scatter 判定复用 `p2pnet_daemon::peer::scatter_decision`（单一事实源，不复制逻辑）。
- [x] 兼容矩阵 + 结构证明测试（ice `tests/fingerprint.rs` + daemon `nat_hint.rs`）：穷举长度 ≤128、`m/a/d/c` 字节一致、往返、裸词/损坏 `parsed=false`、`f==apd ⟹ m==apd`（静态推断下 f 轴 provably 零贡献）、全组合 `scatter_decision == legacy`。
- 落点：`client/nat/src/ice.rs`、`client/daemon/src/peer/connection/nat_hint.rs`、`server/api/device_handlers.go`、`client/cli/src/formatting/peer/utils.rs`。
- **设计说明（f 轴 R1 零行为变化，是结构保证）**：R1 静态推断 `infer_filtering_behavior` 下 `f==apd ⟹ m==apd ⟹` base 已真，故 `|| (f==apd)` 项结构性不可达；`f==EIM ⟹ m==open ⟹ a==stable ⟹` base 假，f 轴整条 no-op。零回归由「全组合 == legacy」测试证明，非仅快照。首个可触发的新行为落在 R1b。

**R1b（BLOCKED — 2026-08-17 §4 前置探测判定）**：让 `f=` 变准 —— 接入 active RFC 5780 CHANGE-REQUEST 三态过滤探测。

- **状态：BLOCKED，不硬做。** 前置生死探测（`scripts/p2wlan-r1b/`，3 生产 STUN × 6 迭代 = 18 样本）证实：**cloudflare / google 的 change-port 均返回 SAME（服务器把 CHANGE-REQUEST 当普通请求从原址回），miwifi NO_RESP**——18 次迭代 **changed-source 响应出现 0 次**。在不支持 CHANGE-REQUEST 的 STUN 上，RFC 5780 filtering 测试逻辑本身歧义（「changed 响应收不到」分不清「我 NAT 过滤」还是「服务器没发」），active 探测无料可喂 → live-safe 探测写出来是永远走 fallback 的死代码。
- **范围（解锁后）**：在生产稳态 gather 里跑**复用 `stun_waiters` 派发机制**的 live-safe CHANGE-REQUEST 探测（命门已核实可解：`query_stun_live_on_socket` + `inbound.rs:219` source-agnostic 派发），使 `filtering_behavior` 独立于 `m=` 取值——尤其能在 `m==EndpointIndependent`（稳定映射）上探出 `f==apd`（EIM+APDF，家网关常见）。
- **触发新行为**：R1b 后 `m==EIM + f==apd + a==stable` 首次使 `|| (f==apd)` 项可达 → 新 client 散射、旧 `.contains` 也命中（`address_or_port_dependent` token）→ 一致，不破坏 R1a 的 provably==legacy。
- **解锁条件**：一台 **honor CHANGE-REQUEST 的 STUN**（本项目全自托管——自托管一台即彻底绕开第三方忽略 change 问题）。届时 `selftest.py` 先证正例可检测、`probe2.py` 指向自托管 STUN 复跑，再启动 R1b 本体。
- **ROI 提示**：R1b 主要收益在 EIM+APDF（家用网关）；**双 CGNAT 主场景（m=APD）无增量**——commit `4e3312f` 已用 `base=(m==apd)` 无条件散射，f 对其无关。故 R1b 非当前最痛点，与 field Gate 排序时 field 优先。
- 原 R1「detection 三态」与 R4「服务端结构化解析」拆分归属：detection 三态 → R1b（本段，BLOCKED）；**服务端不解析**（原 R4 假设被推翻，dumb pipe 更优）→ 永久保持透传，服务端改动止于 cap=128。
- 探测工具与完整证据：`scripts/p2wlan-r1b/README.md`。

### R2 预测引擎升级（中风险，核心收益）
- `client/nat/src/mapping.rs`：
  - predict_ports 改双窗口双向（W=2 默认，向下回绕保护，UINT16 wrap 防护）；
  - 新增 StepLearner（EWMA 差分学习：`next = 0.6*advertised + 0.4*(last_diff)`）替代当前纯差分；
  - 新增 ReverseDetector：batch 内 diff 符号翻转 → 计数 forward/reverse/mixed，reverse 时建议窗口 W+1；
  - 新增 drift 检测：连续 2+ 映射变化偏离模型 → 标记 drift，触发 refresh 重建模。
- `client/daemon/src/udp/outbound.rs`：`build_probe_schedule` 插入**预算分层**：exact→window（predict_ports）→random（birthday 池）→sweep（大步进 8），每层独立预算，上一层全败才进入下一层（对齐 punch-research BudgetScanner）。
- 落点：`client/nat/src/mapping.rs`、`udp/outbound.rs`、`udp/dynamic_punch.rs`（fresh-mapping 批量测量已具备，接 StepLearner）。
- 验收：双 linear 场景 P50 命中轮次 ≤2（nat_sim 回放 + 真实网络）。

### R3 生命周期与缓存（低风险）
- candidate_refresh 循环接入 drift 信号（R2）与 caching hint（对端预测窗口缓存）：cache 命中时跳过重 gather，直接打洞；
- keepalive 参数化（默认 25s，配置可调），与 relay-backoff heartbeat 共存；
- 落点：`client/daemon/src/candidate_refresh/runtime.rs`、`hole_punch.rs`。

### R4 服务端信令 cap 放宽 + hairpin 消费（低风险，服务端小改）
- 服务端（Go）`UpdateDeviceEndpoint`：`nat_type` cap `64 → 128`（R1a 已完成 ✅）。**不引入结构化解析**——dumb pipe 透传更优（原 R4「服务端解析枚举」假设被 R1a 推翻），所有结构化在 Rust 收端。
- `remote_nat_requires_port_scatter` 已结构化消费 `f=`（R1a）；hairpin 字段消费（本地 hairpin=no 时对端直连不可用 → 快速回落中继）留本阶段，待 `h=` 在生产有真实填充后接入（R1 只信令 + 记录 + CLI 展示，不接散射决策）。
- 落点：`server/api/device_handlers.go`（R1a 已改）、`client/daemon/src/peer/connection/nat_hint.rs`（hairpin 消费待加）。
- 注：信令仅 hint，Direct 提升仍以加密验证 ACK 为准（不改变现有安全模型）。

## 3. 明确不迁移项
- RFC 3489 `NatType` 枚举（Full/Restricted/PortRestricted/Symmetric）保留兼容，但不再作为决策输入；
- `detect()` 简化双服务器法保留为 fallback（服务器不支持 CHANGE-REQUEST 时）；
- punch-research 的 asyncio mock 结构不迁移（仅行为语义迁移到 tokio）。

## 4. 风险与缓解
| 风险 | 缓解 |
|---|---|
| CHANGE-REQUEST 探测被现实 NAT 忽略 | no-response 三态 → 按 APD/deny 保守决策 + 全量散射兜底 |
| 预测窗口过大挤占信号带宽 | MAX_SIGNAL_FRESH_WINDOW_CANDIDATES=96 截断保留，按置信度排序 |
| 服务端格式演进兼容 | nat_type TEXT 字段前缀版本化（`p2v2:...`），旧客户端字符串直接透传 |
| 迁移回归无环境 | nat_sim 全谱矩阵（36 组）作为 Rust 集成测试向量库回放（GTest/nextest） |

## 5. 验收与回放
1. nat_sim 36 组矩阵注入 → Rust 检测/预测模块输出一致（mapping/allocation/filtering/hairpin/step）；
2. 网格推荐参数（见 RECOMMENDED_PARAMS.md）作为 Rust 默认配置；
3. 双 linear 场景真实网络 P50 建立 ≤1.5s、成功率 ≥95%（Gate2 实测）。

## 6. 里程碑
- R1a: 指纹信令 schema（`p2v2:`）+ 散射决策结构化消费 + 兼容层 + 服务端 cap（✅ 已完成）
- R1b: active RFC 5780 filtering 探测，使 `f=` 独立于 `m=` 变准（**BLOCKED**，2026-08-17 §4 探测：生产 STUN 不 honor CHANGE-REQUEST，解锁需自托管 CHANGE-REQUEST STUN，见 §2 R1b 段）
- R2: 预测升级 + 预算分层（2 周）
- R3: 生命周期接入（1 周）
- R4: 服务端 cap（R1a 已完成）+ hairpin 消费（待 `h=` 生产填充，1 周）
- 回归：nat_sim 向量库回放 + 真实网络 A/B（1 周）
# Outbound-UDP liveness — 交付说明

分支 `worktree-outbound-liveness`（基座 `cedb991` = origin/main）。16 commits，20 文件，
纯新增（+1574/−0，未改任何既有逻辑行）。

## 1. 关键设计决策

**合法 DNS A query 替代 UU 空包（§3.1 硬要求）**
UU `PunchCheckFireWall` 发 `sendto(b"\x00"*16)` 空包再 `recvfrom`——公网 DNS 对空/非法报文
几乎不回应，"收到响应"这路基本走不到，判定不可靠。本实现构造 19 字节合法 A query
（12 字节 header：ID + RD=0x0100 + QDCOUNT=1；question：单标签 `a`，type A，class IN），
DNS 服务器对合法 query 几乎必然回应（NOERROR / NXDOMAIN 都算可达）。字节布局有
`dns_query_is_well_formed` 逐字节断言（RFC 1035）。

**机制/决策归属拆分**
- 机制（DNS 构造 + socket 并行探测 + 三态归并）→ `client/nat/src/outbound_liveness.rs`。
  理由：无 peer 依赖的纯机制，socket 层可注入 mock 独立测；与 `MappingBehavior::UdpBlocked`
  （ice.rs:114）同族（打洞时刻 vs STUN 时刻的同一"出站可达"事实，交叉印证但不替代）。
- 决策（TTL 缓存 keyed `(peer, generation)` + 事件 + 下一 tick 迁移）→ daemon
  `PeerManager`（`peer/manager/outbound_liveness.rs`，经 `include!` 挂进 `peer` 作用域）。

**保守三态（只有 Blocked 才加速，Unknown 永不决策）**
`Ok`=任一 target 响应；`Blocked`=全部 target×全部轮静默；`Unknown`=socket/系统错误。
"只有干净的静默才算 Blocked"这条不变量在**三层**都有直接测试保护：
- nat `probe`：spawned future panic（`JoinError`）→ Unknown（`panicked_probe_future_maps_to_unknown_not_blocked`）
- daemon 探测闭包：bind 失败 / send 失败 / recv I/O error → SocketError → Unknown
- daemon `apply`：只有 `Blocked` 才 `record_failure(firewall_blocked)` + stage→RelayBackoff

**收口点修正（相对任务 §2 假设）**
任务假设插在 `advance_recovery_stage_after_no_ack`——那里 `ScatterExtended => ScatterExtended`
是停留、不进 RelayBackoff。真实收口在 `probe_loop.rs` 的 0-ACK 判定点
（`success_count_after == success_count_before`），加约束 `stage==ScatterExtended && window_completed`
（`window_completed`：非生日扫 = 全窗已发；生日扫 = cursor 已推进，排除没发完的窗口）。

## 2. 三个 blocker（P1/P2/P3）+ 死锁 的落实

- **P1（spawn，不内联 await）**：触发点 `probe_loop.rs` 0-ACK 处 `tokio::spawn` 出去
  （`run_outbound_liveness_probe`），**不持有任何 peers 写锁跨 socket I/O**（socket I/O 在锁外，
  `commit_liveness` 之后才分段短锁 cache→drop→connections→drop）。加速**不在探测任务做**，
  而由下一 tick admission 消费缓存。
- **P2（并行轮次 ≤3s）**：`probe` 每轮用 `JoinSet` 对全部 target **并行**（各 1500ms），
  `retries`(=2) 轮，任一轮有响应提前停。总时延 ≤ `retries×timeout`=3s（非顺序 ~18s）。
  每个 (round,target) **独立 bind socket**，`recv_from` 隔离，per-target 归因可靠。
- **P3（spawn 后解耦）**：657 处不再断言"conn 已在 FallbackToRelay"，与后续
  `match birthday_window_completion` 的 transition 子路彻底解耦；`fail_reason` 由
  `apply_cached_liveness_block` **一次性**写（`consumed` 标记），不与既有 transition 竞争。
- **死锁（review 抓到，最险）**：`recovery_epoch_admit` 在 `epochs.write()` 之后、
  `mark_recovery_relay_backoff` 会**再取同一把非可重入写锁** → 消费点必须放在
  `Superseded` 早退之后、`epochs.write()` **之前**（唯一无锁缝隙）。`liveness_blocked_applied_exactly_once_at_admit`
  能跑通（不挂）即实证无死锁。另加 epoch 存在性 guard：首 admit（epoch 尚未建）不消费，
  避免把 verdict 消耗在无法迁移 stage 的空 epoch 上。

## 3. 与 relay-first 3s SLO 的交互

liveness **只**影响"何时/为何转 relay"，**从不** gate relay、**从不**改 Direct 提升的
加密验证 ACK。被墙场景：全窗扫满 → 探测（≤3s）→ 下一 tick admission 消费 →
stage ScatterExtended→RelayBackoff（96 可信心跳）+ `firewall_blocked`。即"从扫满到转
relay"的额外延迟 = 探测时长（≈3s），**而非再等一个 epoch 的 60s+ budget backoff**。
`Ok` 不加速（可能是 transient 黑洞，保持 flat cadence 继续重试）。

## 4. pre-flight：实现但默认关（`udp_liveness_pre_flight=false`）

只读门（`pre_flight_liveness_blocked`）：启用且缓存有**新鲜 Blocked** 时跳过本次打洞
（relay 保底）。默认关的理由：主触发（宽扫后）已消除"被墙多等一个 epoch"的核心痛点；
pre-flight 在 punch 前抑制扫描，爆炸半径更大，且"跳过"比"事后归因"更难自愈。TTL 保证
不会因一次 transient 全静而永久停打。有单测覆盖（off 永不拦 / on 仅拦新鲜 Blocked / 过期自愈）。

## 5. 可观测

- `record_direct_event("outbound_liveness", ...)`：每 target `(ip:port, responded, ms)` +
  总耗时 + 三态（探测时落盘）。
- `PathHealth.last_liveness`（代际变即清）→ 经 `PathHealthDiagnostics.last_liveness` 进
  `/status` JSON → CLI per-peer 渲染「出站 UDP 被阻断，已转中继 / 可达(另有原因) / 探测异常(未据此决策)」。
- `REASON_DIRECT_FIREWALL_BLOCKED = "firewall_blocked"` 落 `direct_health.last_error_code`。

## 6. 配置（`config/types.rs` `NetworkConfig`，全带 serde default）

`udp_liveness_enabled=true` / `udp_liveness_targets=[223.5.5.5:53, 119.29.29.29:53,
114.114.114.114:53, 8.8.8.8:53]` / `udp_liveness_timeout_ms=1500` /
`udp_liveness_ttl_ms=30000` / `udp_liveness_retries=2` / `udp_liveness_pre_flight=false`。
> 注：仓库 `.env.example` 被 `.gitignore`（`.env.*`）忽略，非 tracked 文件；配置项落 JSON
> `NetworkConfig`（serde 自文档化），operator 说明见 `live_check.sh` 头部 + 本文件。

## 7. 已知局限

- `Blocked` 是"大概率被拦"非绝对——靠多目标冗余把正常网误判率压到 ≈0（spec §5.5）。
- 探测只看"有没有回应"，**不解析** DNS 答案体（NOERROR/NXDOMAIN 同视为可达）。
- `Unknown` 永不据此决策（socket 建不出/系统错 ≠ 防火墙证据）。
- 不解决 C=0（双 APD 无互放行端点对）——那是窗口 miss，liveness 只会判 `Ok` 并如实归因。
- per-target 明细经事件落盘（非缓存），缓存只存 verdict/TTL/consumed。

## 8. 门禁状态（本 sandbox）

- `cargo clippy --workspace --all-targets --all-features -- -D warnings` → **clean**（全部 9 members）。
- `cargo test -p p2wlan-daemon` → 838 passed / **4 failed**（全是 sandbox 环境依赖型基线失败：
  socket-pool / overlay / network-identity / advertised-bind，与 `daemon-lib-preexisting-test-failures`
  记录逐一对应，非回归）。
- `cargo test -p p2pnet-nat` → 150 passed（144 baseline + 6 liveness）。
- `cargo test -p p2wlan-cli` → 30 passed（+1 liveness 渲染测试）。
- `cargo fmt --all --check` → 本特性 20 文件全 clean；**5 个预存 foreign 文件**
  （daemon lib.rs/netenv.rs/relay_runtime.rs + nat adaptive.rs/mapping.rs）在本机 rustfmt
  1.9.0 下 dirty——已用 `git diff cedb991..HEAD` 确认**均非本分支改动**，是共享 baseline 的
  rustfmt 版本 skew（其中 adaptive/mapping 是任务 §4 明确不碰的文件）。未随本特性 reformat。
- live 验证：`scripts/outbound-liveness/live_check.sh`（blocked/normal 两场景 harness，已用
  合成 fixture 验证解析 + PASS/FAIL 逻辑）+ `RESULT_TEMPLATE.md`（Gate 报告模板）。真实网络
  Gate 数据需你在被拦网络/正常网络上跑 daemon 后填充。

## 9. 测试索引（新增）

| 层 | 测试 | 覆盖 |
|---|---|---|
| nat | `dns_query_is_well_formed` | DNS 字节布局 |
| nat | `verdict_ok/blocked/unknown/nxdomain...` | 三态 + early-stop 反证 |
| nat | `panicked_probe_future_maps_to_unknown_not_blocked` | panic→Unknown（保守不变量）|
| daemon part15 | `liveness_ttl_cache_hit/expiry/generation_change` | TTL 去重 + 代际失效 |
| daemon part15 | `liveness_blocked_applied_exactly_once_at_admit` | 消费 + 恰好一次 + 无死锁 |
| daemon part15 | `liveness_ok_verdict_is_recorded_but_never_applied` | Ok 不决策 |
| daemon part15 | `liveness_pre_flight_off_never_blocks` / `_on_blocks_only_on_fresh_blocked` | pre-flight 门 + TTL 自愈 |
| daemon part15 | `scatter_extended_0ack_{blocked,ok,unknown}_...` | **集成**：0-ACK+verdict → 迁移/归因 |
| cli part02 | `doctor_formats_direct_liveness_verdict` | CLI 渲染 |

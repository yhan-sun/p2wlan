# 路径可观测性参考

路径观测只读取已提交的 Direct/Relay 状态，不做路径决策、不写 socket、不阻塞数据面。唯一的状态转换入口是 commit_path_transition；每个 peer 最多保留 32 条转换记录，动态标签不包含 peer id、endpoint、IP、session id 或任意错误文本。

本地认证的 GET /status 响应附带进程内递增的 X-P2WLAN-Status-Request-ID 响应头，用于把同主机客户端的连接/首字节耗时与 daemon 快照、序列化和写回阶段对应起来。诊断日志只记录请求编号、进程编号、耗时和快照重试/回退状态，不记录授权头、token 或 peer 身份；JSON schema 不依赖该可选响应头。

状态对象带 schema_version、network_generation、peer_session_generation、remote_candidate_epoch、lifecycle、current_path、previous_path、transition_reason、path_age_ms、direct_state、relay_state、recovery_state、selected_path_mtu 和 selected_udp_datagram_size。

固定指标字段包括：

    accepted_transitions
    accepted_observations
    duplicate_events
    rejected_transitions
    path_changes
    direct_attempts
    direct_retries
    direct_validations
    direct_successes
    direct_failures
    validation_failures
    relay_confirmations
    relay_fallbacks
    relay_failures
    candidate_refreshes
    control_reconnects
    network_generation_changes
    lifecycle_resets
    dplpmtud_changes
    active_tasks
    active_sockets
    dropped_transition_events
    direct_time_to_connect_ms

direct_time_to_connect_ms 使用固定边界 50、100、250、500、1000、3000、10000、30000 毫秒和一个溢出桶。Direct-first 使用 `direct_first_started`、`direct_first_deadline` 和 `direct_first_satisfied` 记录权威准入窗口事件；事件本身不代表 Direct 成功或 Relay 已发送业务。reason code 是封闭集合；诊断文本不能变成指标标签。旧客户端缺少该对象时按 schema 0 读取，不能把缺失字段解释成当前路径成功。

control_reconnect_counter_survives_timeline_eviction 是必须保持的回归契约：进程时间线淘汰旧记录后，Control 重连计数仍来自有界状态，而不是依赖已被淘汰的事件。

## Hard↔Hard attempt report

实验环境变量 P2WLAN_EXPERIMENT_* 标签和信令延迟只在显式 --hard-hard-experiment-only 模式下生效；信令延迟默认为 0，最大 2000 ms。普通模式即使继承这些环境变量，也不会增加延迟或把实验标签写入 attempt 报告。

`/status` 的 `peers[].direct_events[]` 在 `stage=hard_hard_attempt_report` 时携带 schema 2 的 `hard_hard_attempt`。它是现有会话状态所有者导出的只读终态记录，不参与候选排序、发送准入、路径选择或取消判定。写入前会再次核对 network generation、peer session generation、remote candidate epoch、profile generation、punch generation、socket index、session token 和 attempt；旧会话的迟到结果不会记到新会话。`plan_tag` 仅用于把同一会话的单个 rendezvous 计划在两端配对，与 `session_tag` 分离。

身份字段包含构建源码、比较基线、build ID、实验 variant/scenario/seed、角色与 attempt。原始 session、IP 和端口不进入结构化记录；`session_tag` 与 `target_order_tags` 是会话加盐的短 SHA-256 标签，只用于同一 attempt 内关联和保留候选顺序，不能当作跨会话身份。

候选与发送成本保持不同口径：

- `requested`、`generated`、`unique`、`advertised` 分别表示请求、模型输出、去重和本端已交给信令 API 的候选数。`parsed_targets_for_plan` 只表示到达本端并解析后进入该计划的目标数；它不是信令原始接收量，也不表示解析前数量或裁剪前数量；
- `planned_targets`、`planned_sockets`、`planned_socket_target_combinations`、`planned_logical_probes` 与 `planned_physical_datagram_cap` 描述有界计划；
- `attempted_targets` 是至少收到一次逻辑探测的唯一远端目标数；重复波次由 `logical_probes_attempted`、`logical_probes_sent` 单独计数；
- `send_success_datagrams` / `send_success_bytes` 与 send-error 字段描述实际 UDP 系统调用结果。一个逻辑探测可能带一个有界兼容副本，因此物理 datagram 数不能从候选数推导；
- `budget_skipped` 与 `planned_logical_probes_not_attempted` 保留没有执行的计划量；矩阵汇总把后者归为成功后取消、过期、预算拒绝、生命周期失效或未知原因；
- STUN datagram/byte/error/response 单独计费。`candidate_signal_payload_logic_bytes` 只累计候选和来源字符串长度，不是序列化请求、HTTP/WebSocket 帧、TLS 或完整控制传输字节。

`target_order_tags` 保留实际目标顺序，重复目标仍重复出现；`confirmed_target_rank` 在加密验证选中的远端地址属于该计划时记录其从 0 开始的位置，不暴露地址，空值表示未确认 Direct 或确认的是计划外学习地址。`candidate_cap` 与 `truncation_reason` 说明裁剪边界。分类包括 `measurement_insufficient`、`model_unpredictable`、`budget_rejected`、`send_error`、`missed_schedule`、`candidate_not_executed`、`no_response`、`probe_hit_validation_failed`、`cancelled_generation_changed`、`encrypted_validation_completed` 和证据不足时的 `unknown`。最后一个验证阶段不是业务成功；采集器只有在真实业务 ingress 存在时才派生 `direct_business_succeeded`。探测命中不等于加密验证，验证也不等于业务已可用。

时间字段全部来自同一 daemon 进程的单调时钟。`candidate_signal_accepted_at_ms` 只表示本端信令 API 接受 offer，不证明服务端持久化、对端收到信号或双方完成交换。`probe_last_hit_at_ms` 与 `probe_last_hit_source` 表示验证前最后一次认证 Probe 或匹配 ACK，不是首次命中。`measurement_age_at_send_ms`、`measurement_to_first_send_ms`、`last_probe_hit_to_validation_ms` 使用非负差值；缺时间或顺序逆置时为空，不把异常压成零。它们分别描述测量新鲜度、测量到首发、最后命中到验证。

矩阵采集器只在验证 session、Direct commit sequence、transport instance 和 socket index 全部与对应 timeline 事件一致时，才把业务里程碑归给该 attempt。仅有 peer/network generation，或任一身份字段缺失/不匹配时，`business_ready_at_ms`、`first_business_success_at_ms` 和派生的 `validation_to_first_business_ms` 保持未知并标为 `not_attributable`；不从同 generation 的其他 attempt 回填。`connection_to_first_business_ms` 目前缺少可与该 attempt 精确关联的连接开始身份，因此保持未知。请求级真实双向业务证据仍由既有 `first_usable_summaries` 判定，两种统计口径不得互相替代。

`business_ready_at_ms` 只取生产出站选择器观察到 `direct_business_mtu_ready` 的时刻；`first_business_success_at_ms` 只取精确身份匹配的 Direct `business_ingress_observed`。两者都不能用 active path、probe/ACK 或加密验证时刻代替。两者分别描述本端出站就绪和入站交付，均须晚于本端加密验证，但在双向业务中互相没有先后因果约束：对端可能在本端出站 MTU 探索完成前先发送一帧合法业务。不同 daemon 的绝对毫秒值不能互减。

## Hard↔Hard NAT 实验入口

独立矩阵入口不会替换既有 Direct、Relay 或 fail-closed gate：

    python3 scripts/nat-sim/run-hard-hard-matrix.py --list
    python3 scripts/nat-sim/run-hard-hard-matrix.py \
      --scenario equal-step \
      --scenario random-high-entropy-negative \
      --rounds 1 \
      --output /absolute/path/outside/repository/hard-hard-evidence

`--help` 列出完整参数。输出目录必须是仓库外尚不存在的绝对路径，创建为仅当前用户可访问；runner 不覆盖或清理已有目录。每个固定 seed 只执行一次，不做诊断重试，原始 stdout/stderr、两端日志/status、NAT trace、进程清理耗时和普通 `nat-evidence.json` 均保留。缺任一侧 typed attempt、首业务证据、健康的 critical task、完整进程回收或原始 trace 时，manifest 失败关闭。

矩阵包含等/异步长、负步长回绕、端口竞争、单/双侧严格过滤、非对称 NAT/STUN/信令/准备延迟、丢包/乱序/重复，以及固定 seed 的高熵随机映射和 Relay 重连。Hard↔Hard 模式最多预建 32 个“仅允许已登记内端发送触发映射”的模拟器公网监听槽，以忠实承载双方同时首发；公网入站不能创建或认领这些槽，其他模式默认关闭。高熵场景是负对照：允许 Direct 失败并以 Relay 有界兜底，但不允许缺证据、任务泄漏或无界退出。取消的 generation/session fencing 由隔离 Rust 回归覆盖；本地双进程模拟不代表两台物理设备、真实运营商 NAT 或公网成功率。

manifest 分开报告 requested 场景/轮次、smoke 执行结果、证据有效性、保护期内 Direct 首业务、Relay-first、Relay 后升级 Direct、固定观测期最终 Direct、全部可读 typed attempt 失败/终态分布、测量年龄与计划偏差、候选执行和确认命中位置、条件延迟样本量、全部 requested 与 valid-only 两套 packet/byte/STUN/候选逻辑 payload 成本、同一 session/plan 的配对和不完整报告数、计划 Socket 峰值、清理耗时、子进程 CPU/RSS 和 critical task 数。部分无效轮次中可读的单侧成本保留，未读到的字段以 unknown/incomplete 表示；完整控制传输字节当前未知。`first_usable` 的请求级路径结果、attempt 级身份归因和有效轮次统计是独立分母。资源数包含本地构建、启动、实验与清理，不是跨主机性能比较；本轮没有隔离的遥测开/关性能 A/B，只用确定性回归约束候选顺序、预算、路径和取消不变。它不把不同 seed 当作不同真实网络，也不从无因果证据的数据宣称成功率提升。

## 活动路径遥测契约（path_telemetry_v1）

daemon 通过异步非阻塞 sidecar 向 Control 上报权威活动路径状态。遥测通道优先复用 WebSocket 信令连接（通过 ready 消息中的 `path_telemetry_v1` 协商），支持 HTTP `POST /api/v1/telemetry/paths` 作为断连或无 WebSocket 时的回退通道。

### 隐私硬约束

遥测载荷严格遵循零泄露原则：
- 严禁携带、传输或持久化任何 IP 地址、端口号、NAT 候选 socket 地址、WireGuard 密钥或数据包载荷。
- 路径状态仅抽象分类为 `direct`、`relay` 或 `none`。
- 状态迁移原因代码严格限制在已定义的封闭集合（如 `initial`、`direct_committed`、`relay_peer_confirmed`、`direct_path_failed`、`relay_path_failed`、`network_generation_advanced` 等）。

### 资源有界性

- daemon 脏节点待发送队列容量硬上限为 128 个 peer；并发状态变迁对同一对端合并最新快照（coalesced）。
- 每条对端观测最多附带最近 32 条本地迁移记录。
- Control 数据库持久化：`peer_path_observations` 表保留每个有向对 `(reporting_device, remote_device, network)` 的最新权威状态；`peer_path_transitions` 历史表对每个有向对保留上限 50 条最近记录，超出自动清理。


### 管理台呈现

Admin Connections 保留遥测的单向语义，不把两个方向合并成新的共享真相。列表与详情可以同时出现 `A → B = direct`、`B → A = relay`。Live Topology 必须先限定到单个网络，默认只把 `fresh=true` 的权威观测画成活动边；stale / reporter offline 记录仅在用户显式开启后以旧观测样式显示。

资源关系图继续使用 `graph_kind=control_relationships`，只表达账号、网络、房间、设备 membership 与 attachment。Connections 和 Relationships 不使用对方的数据推断自己的边。


## Connection Health 派生规则

Control 的 Connection Health 不是新的路径状态所有者。它只在 Admin 请求时读取当前 `peer_path_observations` 和已保留的 `peer_path_transitions`，按请求窗口派生运维 attention signals；结果不会反写 daemon、不会改变 Direct/Relay 选择，也没有单独的告警生命周期。

默认窗口为 3600 秒，允许 60–86400 秒。固定阈值为每方向窗口内至少 4 次 Direct↔Relay 切换触发 `frequent_path_switching`，至少 3 次显式 Direct/Relay failure reason 触发 `repeated_path_failures`。stable Relay observation 只进入路径分布统计，不自动代表降级或故障。

新鲜度继续复用 `DeviceOnlineTTL`：reporter heartbeat 失效时分类为 `reporter_offline`；reporter 仍在线但 observation 过期时分类为 `stale_observation`；fresh observation 且 peer lifecycle 为 `online`、同时没有 committed `current_path` 时分类为 `no_active_path`；`offline` / `unbound` 生命周期没有路径属于预期状态，不产生该信号。validation RTT 统计仅使用 fresh observation 中已有的最近验证样本。

每个方向的 transition history 仍受 50 条上限约束，所以当单方向在查询窗口内产生超过 50 条迁移时，path switch / failure 计数只能视为当前保留历史上的下界，不能作为完整长期 SLA 指标。


## 小时级 Connection Trends

Control 额外维护有界的 `connection_metric_hourly` 聚合，用于比每方向 50 条 transition history 更长的运维趋势窗口。该聚合不是新的路径状态所有者：它只在一条 path telemetry observation 通过现有 session/generation/revision fencing 并与 authoritative snapshot 同一 SQLite 事务提交时累加。

固定规则：

- bucket 固定为 1 小时，按 Control 接收时间归桶；
- 每个 network 每小时最多 1 行，不保存 peer/device 级长期明细；
- 保留 720 小时（30 天），新 telemetry 写入时同步清理更早 bucket；
- accepted、non-resync committed observation 才计 sample；duplicate、rejected、显式 resync，以及 `registration_seq` 前进后的新 owner 首次权威快照重同步都不计趋势；owner advance 仍正常更新 latest snapshot 与 fencing 状态，但不会制造长期 sample、switch 或 failure；
- `direct_observation_samples` / `relay_observation_samples` / `no_path_observation_samples` 是 observation sample 数，不代表路径在线时长、流量占比或 SLA；
- `path_switches` 只统计服务端已存在 Direct/Relay snapshot 与新 accepted snapshot 之间真正的 Direct↔Relay 切换；首次 observation、lifecycle-only 变化和 path→none 不算 Direct↔Relay switch；
- failure 只在 transition history 真正记录 `direct_probe_failed`、`direct_path_failed` 或 `relay_path_failed` 时累加，不把重复 snapshot 当新失败；
- validation RTT 使用固定累计 histogram 上界 50、100、250、500、1000、3000、10000 ms，并保留 >10000 ms overflow bucket；超过 24 小时的异常 RTT 输入按无效样本丢弃，不写入 authoritative RTT snapshot 或趋势；API 的 p50/p95 字段是 histogram upper bound，不是精确 percentile，落入 overflow 时不伪造上界。

`GET /admin/api/v1/connection-trends` 默认返回最近 24 个小时 bucket，支持 `window_hours=1..720` 与可选 `network_id`。响应固定补齐缺失小时为零 bucket，因此调用方不需要把“没有 sample”误读成丢失数据。全局查询按小时汇总所有 network，network-scoped 查询只读取指定 network。

当前 Rust telemetry wire 的 `selected_mtu`、`last_direct_latency_ms`、`last_relay_latency_ms` 会在 Control ingestion 时兼容映射到 authoritative snapshot 的 `selected_path_mtu` / 当前路径 validation RTT 字段；该映射只修正字段命名差异，不改变 daemon 的路径决策。

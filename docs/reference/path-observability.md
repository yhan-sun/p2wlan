# 路径可观测性参考

路径观测只读取已提交的 Direct/Relay 状态，不做路径决策、不写 socket、不阻塞数据面。唯一的状态转换入口是 commit_path_transition；每个 peer 最多保留 32 条转换记录，动态标签不包含 peer id、endpoint、IP、session id 或任意错误文本。

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

direct_time_to_connect_ms 使用固定边界 50、100、250、500、1000、3000、10000、30000 毫秒和一个溢出桶。reason code 是封闭集合；诊断文本不能变成指标标签。旧客户端缺少该对象时按 schema 0 读取，不能把缺失字段解释成当前路径成功。

control_reconnect_counter_survives_timeline_eviction 是必须保持的回归契约：进程时间线淘汰旧记录后，Control 重连计数仍来自有界状态，而不是依赖已被淘汰的事件。

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

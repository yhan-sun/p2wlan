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

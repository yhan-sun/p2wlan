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

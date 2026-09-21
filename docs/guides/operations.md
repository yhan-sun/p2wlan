# 运维指南

## 服务

    sudo p2wlan-server status --service all
    sudo p2wlan-server start --service all
    sudo p2wlan-server stop --service all
    sudo p2wlan-server restart --service all
    sudo p2wlan-server check --service all
    sudo p2wlan-server doctor --service all

Control 的 /health 只表示进程可响应；Relay 的 /readyz 还要求撤权 feed 已同步并在有效时间内。`check` 用于服务级健康判定；`doctor` 额外检查发布包、systemd、Admin 凭据、SQLite、Relay TLS、备份和数据盘空间，并把非致命项标成 warning。两者都不能证明真实公网入口、TUN 或应用业务已经端到端可达。

## 管理控制台

Control 可选提供 `/admin/` 只读管理台。只有配置独立的 `CONTROL_ADMIN_TOKEN` 后该入口才存在；未配置时 `/admin` 与 `/admin/*` 返回 404。管理员令牌至少 32 个字符，通过 `Authorization: Bearer` 访问管理 API，不复用账号 JWT、设备凭据或 Relay 凭据。

管理台以账号为一级运维实体，可查看所有账号的设备在线情况、网络与房间关系、最近活动，以及单账号详情。原先的“拓扑”入口现在明确命名为“资源关系”：全局和单账号关系图都只来自 Control 已提交关系，包括账号到网络/房间的 membership、网络到设备的 attachment，以及可选显示的数据库待处理 signaling。单账号关系图会保留共享网络或房间里的对端账号与设备，不会把共享关系错误裁掉。

大规模部署中，全局拓扑按稳定账号 ID 游标分批读取，并受明确的节点/边预算保护。响应会返回已加载账号数、是否完整以及预算不足原因；达到预算时管理台显示“不完整”并要求下钻到具体账号，而不是静默截断后仍声称全局图完整。账号列表同样使用稳定 ID 游标，因此设备心跳改变 `last_seen` 时不会导致翻页重复或漏行。网络和房间列表按页读取，不在打开页面时一次扫描全部记录。

资源关系图中的账号颜色只用于稳定区分身份；设备的绿色/灰色状态点表示 Control 记录的 online 状态；待处理 signaling 默认隐藏，打开后以琥珀色虚线显示。搜索会只保留匹配资源及其一跳上下文，避免把不相关分支继续留成低透明度“毛线团”。资源关系图只展示 Control 确认的资源拓扑，不会把 `relay_rtt_ms`、候选信息或 signaling 猜测推断成数据面连接。真实数据面活动路径完全由各 daemon 端点权威上报并持久化，不与资源关系图混淆。

管理台还展示 Control 数据库和当前 Control 进程能直接确认的网络、房间、设备、活动隧道、待处理信令和构建信息。设备的 `online`、Relay RTT 或 Control 健康状态都不能单独证明虚拟 IP 业务已经双向可达。

### Connections 与路径观测

管理台的 **Connections** 工作区与“资源关系”是两个独立视图：资源关系回答账号、网络、房间和设备之间的 membership / attachment；Connections 只读取客户端 daemon 已提交并由 Control 持久化的单向活动路径观测，不根据 signaling、Relay RTT 或 membership 推断 Direct / Relay。

Connections 默认使用列表视图，支持服务端搜索设备名、账号名或网络名，并按 `network_id`、`account_id`、`device_id`、`path`（direct / relay / none）与 `freshness`（fresh / stale）过滤。`GET /admin/api/v1/connections` 使用 `limit` / `offset` 分页。条目始终保持方向性：`A → B` 与 `B → A` 是两个独立观测；stale 或 reporter offline 的记录只表示最后一次已知路径，不等于当前仍存在活动连接。

选择单个网络后可切换到 Live Topology。拓扑默认只画 fresh authoritative observations；显式开启 stale 后才以弱化虚线显示旧观测。大规模网络受前端明确的连接预算保护，达到预算会提示收紧搜索或路径过滤，不会静默把局部图声称为完整网络。

点击连接列表行或拓扑边会打开当前方向的只读详情与迁移时间线。`GET /admin/api/v1/connection-transitions` 按 `reporting_device_id`、`remote_device_id`、`network_id` 查询，并使用 `limit` / `cursor` 分页；每对设备最多保留 50 条最近迁移记录。路径观测仍不证明远端具体应用端口一定可达，最终业务判断需要实际虚拟 IP 流量验证。

### Connection Health 与 attention signals

`GET /admin/api/v1/connection-health` 在请求时从 latest authoritative observations 和受限 transition history 派生运维信号，不新增独立 health 状态机，也不持久化告警状态。接口支持 `network_id`、`account_id` / `user_id`、`device_id` 作用域；`window_seconds` 默认 3600 秒，可选 60–86400 秒；`limit` 只限制返回的 attention connection 数量，默认 50、最大 100，同时响应保留准确的 `alerts_total`。

summary 分开统计 fresh、stale、reporter offline、fresh Direct、fresh Relay、`fresh_online_no_path`，以及窗口内 Direct↔Relay path switch、显式 Direct/Relay failure reason 和 validation RTT 样本。`fresh_online_no_path` 只统计 lifecycle=`online` 且没有 committed path 的 fresh observation。Relay 本身是正常路径类别，不会因为当前路径为 Relay 就产生告警；`last_validation_rtt_ms` 及其聚合也只表示最近一次验证样本，不是持续实时 RTT。

attention signal 是固定、可解释的条件：

- `reporter_offline`：上报端 heartbeat lease 已失效；
- `stale_observation`：上报端仍在线，但最新路径观测已超过 freshness lease；
- `no_active_path`：观测仍 fresh、peer lifecycle 为 `online`，但 daemon 没有 committed active path；明确 `offline` / `unbound` 的 peer 没有路径不会被误报；
- `frequent_path_switching`：请求窗口内至少 4 次已记录的 Direct↔Relay 切换；
- `repeated_path_failures`：请求窗口内至少 3 次显式 `direct_probe_failed` / `direct_path_failed` / `relay_path_failed`。

阈值会随响应一起返回，不作为隐藏评分。transition history 每个方向最多保留 50 条，因此在极端高频切换超过保留上限时，窗口派生计数可能是下界；该接口不应被解释为完整长期时序分析。

管理台提供独立的 **连接健康** 工作区消费该接口。Dashboard 只展示最近 1 小时的轻量摘要；`/admin/health` 支持按 Network scope 查看 1h / 6h / 24h 窗口，直接展示 fresh / stale / reporter offline、Direct / Relay、online-no-path、路径切换、显式失败与 validation RTT 样本。页面不会计算综合健康分，也不会把 Relay 本身着色成故障。

Needs attention 列表逐条显示服务端返回的固定 signal 和阈值相关计数。点击某一项会读取相同 `(network, reporting device, remote device)` 的最新 directional Connection，并打开与 Connections 工作区共用的只读详情 / transition timeline；Health UI 不维护第二份连接详情或路径状态。

### Connection Trends

`GET /admin/api/v1/connection-trends` 提供 1 小时粒度、最多 30 天的只读长期趋势基础数据。默认 `window_hours=24`，允许 1–720；可传 `network_id` 下钻单个 network，不传时按小时聚合所有 network。

趋势字段包括 accepted committed-observation samples、Direct/Relay/no-path samples、真实 Direct↔Relay switch、显式 Direct/Relay failure，以及 validation RTT count/average/max、固定 histogram 和 p50/p95 histogram upper bound。这里的 observation samples 不是路径在线时长比例；p50/p95 也不是原始 RTT 明细计算出的精确分位数。超过 10 秒的 RTT 进入 overflow bucket，如果目标 percentile 落入 overflow，API 不返回虚假的数值上界。

小时 rollup 每个 network 每小时只有一行并保留 720 小时；不会长期保存 peer/device 级事件明细。当前只提供趋势存储与 API，管理台尚不绘制长期趋势图。

管理台与 Control 使用同一 origin，不需要额外 CORS 放行。公网访问必须继续经过可信 HTTPS 反向代理；浏览器中的管理员令牌按敏感凭据处理，用完后退出管理台并关闭共享终端中的会话。

## 日志与证书

    sudo p2wlan-server logs --service control
    sudo p2wlan-server logs --service relay

日志轮转、访问权限和保留期限由部署者配置。证书续期必须更新实际挂载文件并重载或重启 Relay，再用 TLS 客户端验证证书链和 endpoint；ACME 客户端报告成功不等于 Relay 已加载新证书。

密钥轮换分别处理 JWT、管理控制台令牌、Relay 票据签名 key、撤权 feed token 和 TLS 私钥。只有实现明确支持重叠验证时，才可承诺无中断轮换。

## 数据保护

数据库、配置、日志和 support bundle 都可能含有敏感数据。限制目录权限，备份与生产数据分离，保留恢复演练结果在 PR/Issue 或内部运维系统，不复制到公共 docs。

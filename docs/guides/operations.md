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

管理台与 Control 使用同一 origin，不需要额外 CORS 放行。公网访问必须继续经过可信 HTTPS 反向代理；浏览器中的管理员令牌按敏感凭据处理，用完后退出管理台并关闭共享终端中的会话。

## 日志与证书

    sudo p2wlan-server logs --service control
    sudo p2wlan-server logs --service relay

日志轮转、访问权限和保留期限由部署者配置。证书续期必须更新实际挂载文件并重载或重启 Relay，再用 TLS 客户端验证证书链和 endpoint；ACME 客户端报告成功不等于 Relay 已加载新证书。

密钥轮换分别处理 JWT、管理控制台令牌、Relay 票据签名 key、撤权 feed token 和 TLS 私钥。只有实现明确支持重叠验证时，才可承诺无中断轮换。

## 数据保护

数据库、配置、日志和 support bundle 都可能含有敏感数据。限制目录权限，备份与生产数据分离，保留恢复演练结果在 PR/Issue 或内部运维系统，不复制到公共 docs。

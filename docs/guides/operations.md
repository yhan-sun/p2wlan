# 运维指南

## 服务

    sudo p2wlan-server status --service all
    sudo p2wlan-server start --service all
    sudo p2wlan-server stop --service all
    sudo p2wlan-server restart --service all
    sudo p2wlan-server check --service all

Control 的 /health 只表示进程可响应；Relay 的 /readyz 还要求撤权 feed 已同步并在有效时间内。两者都通过才可把部署标记为健康。

## 管理控制台

Control 可选提供 `/admin/` 只读管理台。只有配置独立的 `CONTROL_ADMIN_TOKEN` 后该入口才存在；未配置时 `/admin` 与 `/admin/*` 返回 404。管理员令牌至少 32 个字符，通过 `Authorization: Bearer` 访问管理 API，不复用账号 JWT、设备凭据或 Relay 凭据。

管理台以账号为一级运维实体，可查看所有账号的设备在线情况、网络与房间关系、最近活动，以及单账号详情。普通账号、设备、网络和房间列表使用快照游标分页；游标固定创建数据的快照边界，并使用稳定 row key 前进，不再依赖会被心跳持续修改的 `last_seen` 作为 offset 分页边界。

拓扑查询使用显式的分页快照协议，不会用一个无界 SQL 查询把全部图数据一次读入内存，也不会用 `LIMIT` 静默裁掉图的一部分。每个响应只返回有界数量的源记录，并通过 opaque cursor 继续下一 phase。全局拓扑默认使用 `summary` 视图，只读取账号、网络/房间和 membership；需要设备、private-default attachment 与待处理 signaling 时再切换到 `full`。单账号详情默认使用 `full`，并按同一快照 cursor 逐页续传。

分页快照冻结新创建实体进入当前遍历的边界；已经存在的记录如果在遍历期间被更新或删除，页面继续反映 Control 当前可确认的事实，而不是伪造历史 MVCC 视图。浏览器切换账号或拓扑视图时会取消不再需要的续传请求；拓扑不再按固定 30 秒周期重新全量抓取，管理员可通过顶部刷新动作显式获取新快照。

全局拓扑和单账号拓扑都来自 Control 已提交关系：账号到网络/房间的 membership、网络到设备的 attachment，以及当前数据库中尚未消费的 signaling。单账号拓扑会保留共享网络或房间里的对端账号与设备，不会把共享关系错误裁掉。legacy `default` 网络仍保持账号私有语义，private default 设备直接挂在自己的账号节点下，不会因为数据库兼容 membership 被画成跨账号共享网络。

拓扑中的账号颜色只用于第一层稳定身份提示；有限色板允许重复，所以每个账号还显示由账号 ID 稳定派生的短码，不能只凭颜色判断账号。设备的绿色/灰色状态点表示 Control 的心跳租约在线状态；琥珀色虚线表示待处理 signaling。当前 Control 不持久化 daemon 选中的实时 Direct/Relay 业务路径，因此管理台不会把 `relay_rtt_ms`、候选信息或 signaling 推断成 Direct/Relay 连接。要判断真实数据面路径和端到端可达性，仍以 daemon 路径观测、客户端诊断和实际业务流量为准。

管理台还展示 Control 数据库和当前 Control 进程能直接确认的网络、房间、设备、活动隧道、待处理信令和构建信息。设备的 online 租约、Relay RTT 或 Control 健康状态都不能单独证明虚拟 IP 业务已经双向可达。

管理台与 Control 使用同一 origin，不需要额外 CORS 放行。公网访问必须继续经过可信 HTTPS 反向代理；浏览器中的管理员令牌按敏感凭据处理，用完后退出管理台并关闭共享终端中的会话。

## 日志与证书

    sudo p2wlan-server logs --service control
    sudo p2wlan-server logs --service relay

日志轮转、访问权限和保留期限由部署者配置。证书续期必须更新实际挂载文件并重载或重启 Relay，再用 TLS 客户端验证证书链和 endpoint；ACME 客户端报告成功不等于 Relay 已加载新证书。

密钥轮换分别处理 JWT、管理控制台令牌、Relay 票据签名 key、撤权 feed token 和 TLS 私钥。只有实现明确支持重叠验证时，才可承诺无中断轮换。

## 数据保护

数据库、配置、日志和 support bundle 都可能含有敏感数据。限制目录权限，备份与生产数据分离，保留恢复演练结果在 PR/Issue 或内部运维系统，不复制到公共 docs。

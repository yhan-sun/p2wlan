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

管理台以账号为一级运维实体，可查看所有账号的设备在线情况、网络与房间关系、最近活动，以及单账号详情。全局拓扑和单账号拓扑都来自 Control 已提交关系：账号到网络/房间的 membership、网络到设备的 attachment，以及当前数据库中尚未消费的 signaling。单账号拓扑会保留共享网络或房间里的对端账号与设备，不会把共享关系错误裁掉。

大规模部署中，全局拓扑按稳定账号 ID 游标分批读取，并受明确的节点/边预算保护。响应会返回已加载账号数、是否完整以及预算不足原因；达到预算时管理台显示“不完整”并要求下钻到具体账号，而不是静默截断后仍声称全局图完整。账号列表同样使用稳定 ID 游标，因此设备心跳改变 `last_seen` 时不会导致翻页重复或漏行。网络和房间列表按页读取，不在打开页面时一次扫描全部记录。

拓扑中的账号颜色只用于稳定区分身份；设备的绿色/灰色状态点表示 Control 记录的 online 状态；琥珀色虚线表示待处理 signaling。当前 Control 不持久化 daemon 选中的实时 Direct/Relay 业务路径，因此管理台不会把 `relay_rtt_ms`、候选信息或 signaling 推断成 Direct/Relay 连接。要判断真实数据面路径和端到端可达性，仍以 daemon 路径观测、客户端诊断和实际业务流量为准。

管理台还展示 Control 数据库和当前 Control 进程能直接确认的网络、房间、设备、活动隧道、待处理信令和构建信息。设备的 `online`、Relay RTT 或 Control 健康状态都不能单独证明虚拟 IP 业务已经双向可达。

管理台与 Control 使用同一 origin，不需要额外 CORS 放行。公网访问必须继续经过可信 HTTPS 反向代理；浏览器中的管理员令牌按敏感凭据处理，用完后退出管理台并关闭共享终端中的会话。

## 日志与证书

    sudo p2wlan-server logs --service control
    sudo p2wlan-server logs --service relay

日志轮转、访问权限和保留期限由部署者配置。证书续期必须更新实际挂载文件并重载或重启 Relay，再用 TLS 客户端验证证书链和 endpoint；ACME 客户端报告成功不等于 Relay 已加载新证书。

密钥轮换分别处理 JWT、管理控制台令牌、Relay 票据签名 key、撤权 feed token 和 TLS 私钥。只有实现明确支持重叠验证时，才可承诺无中断轮换。

## 数据保护

数据库、配置、日志和 support bundle 都可能含有敏感数据。限制目录权限，备份与生产数据分离，保留恢复演练结果在 PR/Issue 或内部运维系统，不复制到公共 docs。
